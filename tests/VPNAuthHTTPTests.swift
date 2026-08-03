import Foundation

private func source(_ chunks: [Data]) -> HTTPReader.ByteSource {
    let box = ChunkBox(chunks)
    return { box.next() }
}

private final class ChunkBox {
    private let chunks: [Data]
    private var i = 0
    init(_ c: [Data]) { chunks = c }
    func next() -> Data {
        guard i < chunks.count else { return Data() }
        defer { i += 1 }
        return chunks[i]
    }
}

private func d(_ s: String) -> Data { Data(s.utf8) }

// Split a string into N-byte chunks to exercise the cross-read accumulation.
private func chunked(_ s: String, every n: Int) -> [Data] {
    let bytes = Array(s.utf8)
    var out: [Data] = []
    var idx = 0
    while idx < bytes.count {
        let end = min(idx + n, bytes.count)
        out.append(Data(bytes[idx..<end]))
        idx = end
    }
    return out
}

func testHTTPReaderContentLength() async {
    R.enter("HTTPReader/Content-Length")
    let raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
    let r = HTTPReader(source: source([d(raw)]))
    do {
        let resp = try await r.readResponse()
        R.assertEqual(resp.status, 200, "status 200")
        R.assertEqual(resp.body, "hello", "body framed by Content-Length")
        R.assertTrue(resp.keepAlive, "keep-alive (no close, definite length)")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderKeepAliveTwoResponses() async {
    R.enter("HTTPReader/keep-alive two responses")
    let r1 = "HTTP/1.1 302 Found\r\nLocation: /+webvpn+/index.html\r\nContent-Length: 0\r\n\r\n"
    let r2 = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nform"
    let r = HTTPReader(source: source([d(r1 + r2)]))
    do {
        let a = try await r.readResponse()
        R.assertEqual(a.status, 302, "first response 302")
        R.assertEqual(a.location ?? "", "/+webvpn+/index.html", "Location parsed")
        R.assertEqual(a.body, "", "empty body (Content-Length 0)")
        R.assertTrue(a.keepAlive, "first stays keep-alive")
        let b = try await r.readResponse()
        R.assertEqual(b.status, 200, "second response off the same buffer")
        R.assertEqual(b.body, "form", "second body intact after leftover carryover")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderSetCookie() async {
    R.enter("HTTPReader/Set-Cookie")
    let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: webvpn=ABC123; path=/; secure\r\nContent-Length: 2\r\n\r\nok"
    let r = HTTPReader(source: source([d(raw)]))
    do {
        let resp = try await r.readResponse()
        let webvpn = resp.cookies.first { $0.0 == "webvpn" }?.1
        R.assertEqual(webvpn ?? "", "ABC123", "webvpn cookie value (attributes stripped)")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderConnectionClose() async {
    R.enter("HTTPReader/Connection: close")
    let raw = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nbye"
    let r = HTTPReader(source: source([d(raw)]))
    do {
        let resp = try await r.readResponse()
        R.assertEqual(resp.body, "bye", "body read")
        R.assertTrue(!resp.keepAlive, "Connection: close → keepAlive false")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderCloseDelimitedBody() async {
    R.enter("HTTPReader/close-delimited body")
    // No Content-Length, no chunked: body runs until the source closes.
    let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<auth id=\"success\"/>"
    let r = HTTPReader(source: source([d(raw)]))   // box returns empty after the one chunk = close
    do {
        let resp = try await r.readResponse()
        R.assertEqual(resp.body, "<auth id=\"success\"/>", "body read until close")
        R.assertTrue(!resp.keepAlive, "close-delimited → keepAlive false")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderChunked() async {
    R.enter("HTTPReader/chunked")
    // "Wiki" + "pedia" in two chunks, then 0-terminator, then a second response.
    let r1 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    let r2 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    let r = HTTPReader(source: source([d(r1 + r2)]))
    do {
        let a = try await r.readResponse()
        R.assertEqual(a.body, "Wikipedia", "chunked body reassembled")
        R.assertTrue(a.keepAlive, "chunked keep-alive")
        let b = try await r.readResponse()
        R.assertEqual(b.body, "hi", "second response after chunked terminator boundary")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderSplitAcrossReads() async {
    R.enter("HTTPReader/split across reads")
    let raw = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
    let r = HTTPReader(source: source(chunked(raw, every: 1)))
    do {
        let resp = try await r.readResponse()
        R.assertEqual(resp.status, 200, "status parsed across 1-byte reads")
        R.assertEqual(resp.body, "hello world", "body assembled across 1-byte reads")
    } catch { R.assertTrue(false, "unexpected throw: \(error)") }
}

func testHTTPReaderTruncatedHeadersThrows() async {
    R.enter("HTTPReader/truncated headers")
    // Close before the blank line → protocol error, not a hang or garbage parse.
    let r = HTTPReader(source: source([d("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n")]))
    do {
        _ = try await r.readResponse()
        R.assertTrue(false, "expected throw on truncated headers")
    } catch {
        R.assertTrue(true, "threw on truncated headers")
    }
}
