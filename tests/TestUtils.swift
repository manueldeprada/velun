import Foundation

final class TestRecorder {
    private(set) var passed = 0
    private(set) var failed = 0
    private(set) var failures: [String] = []
    private var currentSuite: String = "?"

    func enter(_ suite: String) {
        currentSuite = suite
        print("\n## \(suite)")
    }

    func assertTrue(_ cond: @autoclosure () -> Bool, _ name: String,
                    file: String = #fileID, line: Int = #line) {
        if cond() {
            passed += 1
            print("  ✓ \(name)")
        } else {
            failed += 1
            let msg = "[\(currentSuite)] \(name) — assertion failed at \(file):\(line)"
            failures.append(msg)
            print("  ✗ \(name) — at \(file):\(line)")
        }
    }

    func assertEqual<T: Equatable>(_ a: @autoclosure () -> T,
                                   _ b: @autoclosure () -> T,
                                   _ name: String,
                                   file: String = #fileID, line: Int = #line) {
        let av = a(), bv = b()
        if av == bv {
            passed += 1
            print("  ✓ \(name)")
        } else {
            failed += 1
            let msg = "[\(currentSuite)] \(name): expected \(bv), got \(av) at \(file):\(line)"
            failures.append(msg)
            print("  ✗ \(name): expected \(bv), got \(av)")
        }
    }

    func report() -> Int32 {
        let total = passed + failed
        print("\n----------------------------------------")
        if failed == 0 {
            print("ALL OK — \(passed) / \(total) assertions passed")
            return 0
        }
        print("FAILED — \(failed) of \(total) assertions failed")
        for f in failures { print("  • \(f)") }
        return 1
    }
}

let R = TestRecorder()
