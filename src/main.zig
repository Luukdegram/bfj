const std = @import("std");
const os = std.os;
const mem = std.mem;
const Allocator = mem.Allocator;

const page_size = std.mem.page_size;
const Memory = []align(page_size) u8;

pub const Program = []const u8;

const program_memory: [4096]u8 = undefined;
const bracket_stack: std.ArrayList(u32);

/// Parses the given source code into 
pub fn parse(gpa: *Allocator, source: []const u8) error{OutOfMemory}!Program {
    var i: usize = 0;
    var list = std.ArrayList(u8).init(gpa);
    defer list.deinit();
    return while (true) : (i += 1) {
        if (i == source.len) return list.toOwnedSlice();

        switch (source[i]) {
            '>',
            '<',
            '+',
            '-',
            '.',
            ',',
            '[',
            ']',
            => |c| try list.append(c),
            else => continue,
        }
    } else unreachable;
}

const JitProgram = struct {
    /// Stack containing offsets into the `code` list
    stack: std.ArrayList(u32),
    /// List of instructions
    code: std.ArrayList(u8),

    const Error = error{
        OutOfMemory,
        InvalidStack,
    } || os.MMapError || os.MProtectError;

    /// Initializes a new `JitProgram`
    fn init(gpa: *Allocator) JitProgram {
        return .{
            .stack = std.ArrayList(u32).init(gpa),
            .code = std.ArrayList(u8).init(gpa),
        };
    }

    /// Frees all program memory
    fn deinit(self: *JitProgram) void {
        self.stack.deinit();
        self.code.deinit();
        self.* = undefined;
    }

    /// Transpiles the brainfuck program into machine code instructions
    /// and executes them
    /// NOTE: writes the bytes little-endian
    fn run(self: *JitProgram, program: Program) Error!void {
        // const initial_memory = [_]u8{0} ** 30000;
        var initial_memory = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 30000);

        try self.code.appendSlice(&.{ 0x49, 0xBD });
        try self.code.writer().writeIntLittle(usize, @ptrToInt(initial_memory.items.ptr));

        for (program) |instr| switch (instr) {
            // increase pointer by 1
            '>' => try self.code.appendSlice(&.{ 0x49, 0xFF, 0xC5 }), // inc %r13
            // decrease pointer by 1
            '<' => try self.code.appendSlice(&.{ 0x49, 0xFF, 0xCD }), // dec %r13
            // increase value at current pointer by 1
            '+' => try self.code.appendSlice(&.{ 0x41, 0x80, 0x45, 0x00, 0x01 }), // addb $1, 0(%r13)
            // decrease value at current pointer by 1
            '-' => try self.code.appendSlice(&.{ 0x41, 0x80, 0x6D, 0x00, 0x01 }), // sub $1, 0(%r13)
            // Write to stdout
            '.' => {
                try self.code.appendSlice(&.{ 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00 });
                try self.code.appendSlice(&.{ 0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00 });
                try self.code.appendSlice(&.{ 0x4C, 0x89, 0xEE });
                try self.code.appendSlice(&.{ 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 });
                try self.code.appendSlice(&.{ 0x0F, 0x05 });
            },
            // Read from stdind:
            ',' => {
                try self.code.appendSlice(&.{ 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00 });
                try self.code.appendSlice(&.{ 0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00 });
                try self.code.appendSlice(&.{ 0x4C, 0x89, 0xEE });
                try self.code.appendSlice(&.{ 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 });
                try self.code.appendSlice(&.{ 0x0F, 0x05 });
            },
            // jump to closing bracket
            '[' => {
                try self.code.appendSlice(&.{ 0x41, 0x80, 0x7D, 0x00, 0x00 });
                try self.stack.append(@intCast(u32, self.code.items.len));
                try self.code.appendSlice(&.{ 0x0F, 0x84 });
                try self.code.writer().writeIntLittle(u32, 0);
            },
            ']' => {
                const bracket_offset = self.stack.popOrNull() orelse return error.InvalidStack;

                try self.code.appendSlice(&.{ 0x41, 0x80, 0x7D, 0x00, 0x00 });

                const relative_offset = offset(self.code.items.len + 6, bracket_offset + 6);

                // jump if not zero
                try self.code.appendSlice(&.{ 0x0F, 0x85 });
                try self.code.writer().writeIntLittle(u32, relative_offset);

                const forward_offset = offset(bracket_offset + 6, self.code.items.len);
                self.patch(bracket_offset + 2, forward_offset);
            },
            else => unreachable,
        };

        try self.code.append(0xC3); //ret
        const memory = try alloc(self.code.items.len);
        defer free(memory);
        std.mem.copy(u8, memory, self.code.items);
        try makeExecutable(memory);
        const FnType = fn () void;

        const run_jit = @ptrCast(FnType, @alignCast(@alignOf(FnType), memory));
        run_jit();
    }

    /// Calculates the offset between 2 points.
    /// Returns 2s complement if `to` is smaller than `from`
    fn offset(from: usize, to: usize) u32 {
        if (to >= from) return @intCast(u32, to - from);

        const diff = @intCast(u32, from - to);
        return ~diff + 1;
    }

    /// Replaces the value at offset `index` with a u32 `value`
    fn patch(self: *JitProgram, index: usize, value: u32) void {
        std.mem.writeIntLittle(u32, self.code.items[index .. index + 4][0..4], value);
    }

    /// Allocates writable memory for the given size `size`
    fn alloc(size: usize) !Memory {
        return try os.mmap(
            null,
            std.math.max(size, page_size),
            os.PROT_READ | os.PROT_WRITE,
            os.MAP_PRIVATE | os.MAP_ANONYMOUS,
            -1,
            0,
        );
    }

    /// Makes the given memory executable
    fn makeExecutable(memory: Memory) !void {
        try os.mprotect(memory, os.PROT_READ | os.PROT_EXEC);
    }

    fn free(memory: Memory) void {
        os.munmap(memory);
    }
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const program = try parse(&gpa.allocator, test_data);
    defer gpa.allocator.free(program);

    var jit = JitProgram.init(&gpa.allocator);
    defer jit.deinit();

    try jit.run(program);
}

const test_data =
    \\ ++++++++ ++++++++ ++++++++ ++++++++ ++++++++ ++++++++
    \\ >+++++
    \\ [<+.>-]
;
