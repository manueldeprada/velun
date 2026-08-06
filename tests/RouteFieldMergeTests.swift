import Foundation

func testRouteFieldMerge() {
    R.enter("RouteFieldMerge.merge")

    R.assertEqual(RouteFieldMerge.merge(field: "", learned: ["10.15.1.40/32"]),
                  "10.15.1.40/32", "learned /32 lands in an empty field")

    R.assertEqual(RouteFieldMerge.merge(field: "10.3.0.0/16", learned: ["10.15.1.40/32"]),
                  "10.3.0.0/16 10.15.1.40/32", "appended after existing entries")

    R.assertTrue(RouteFieldMerge.merge(field: "10.15.0.0/16", learned: ["10.15.1.40/32"]) == nil,
                 "already covered → nil (no persist)")

    R.assertTrue(RouteFieldMerge.merge(field: "10.15.1.40/32", learned: ["10.15.1.40/32"]) == nil,
                 "exact duplicate → nil")

    R.assertEqual(RouteFieldMerge.merge(field: "10.3.0.0/16 10.15.1.40/32", learned: ["10.15.1.7/32"]),
                  "10.3.0.0/16 10.15.1.0/24", "existing + learned /32 in one /24 → /24")

    // Two learned /32s in one /24 arriving together.
    R.assertEqual(RouteFieldMerge.merge(field: "", learned: ["10.15.1.40/32", "10.15.1.7/32"]),
                  "10.15.1.0/24", "two learned /32s in one /24 → /24")

    // An extension-coalesced /24 absorbs a saved /32 inside it.
    R.assertEqual(RouteFieldMerge.merge(field: "10.15.1.40/32", learned: ["10.15.1.0/24"]),
                  "10.15.1.0/24", "learned /24 absorbs the saved /32")

    // User-typed /32 pairs with no learned member in their /24 stay as typed.
    R.assertEqual(RouteFieldMerge.merge(field: "1.2.3.4/32 1.2.3.5/32", learned: ["10.15.1.40/32"]),
                  "1.2.3.4/32 1.2.3.5/32 10.15.1.40/32", "user /32s untouched without a learned sibling")

    // Unparseable tokens survive verbatim, in place.
    R.assertEqual(RouteFieldMerge.merge(field: "garbage 10.3.0.0/16", learned: ["194.15.137.55/32"]),
                  "garbage 10.3.0.0/16 194.15.137.55/32", "unparseable token kept")

    // Comma-separated fields re-emit space-separated but keep entries.
    R.assertEqual(RouteFieldMerge.merge(field: "10.3.0.0/16,10.4.0.0/16", learned: ["10.15.1.40/32"]),
                  "10.3.0.0/16 10.4.0.0/16 10.15.1.40/32", "comma-separated field parsed")

    // Multiple learned entries in different /24s: sorted, appended.
    R.assertEqual(RouteFieldMerge.merge(field: "10.3.0.0/16",
                                        learned: ["194.15.137.55/32", "10.15.1.40/32"]),
                  "10.3.0.0/16 10.15.1.40/32 194.15.137.55/32", "additions sorted")

    // A bare IP in the field (no /len) counts as a /32 for coalescing.
    R.assertEqual(RouteFieldMerge.merge(field: "10.15.1.40", learned: ["10.15.1.7/32"]),
                  "10.15.1.0/24", "bare-IP token treated as /32")
}
