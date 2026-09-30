# Campaign mode

One vendor, several products, shared components. Hunt the portfolio, not the product.

```bash
for t in /targets/*.msi /targets/*.exe; do
  scripts/hunt.sh --target "$t" --name "$(basename "${t%.*}")"
done
```

Then correlate across `loot/*/`:

```bash
# which binaries (by sha256) are shared between products?
jq -r '.files[] | "\(.sha256) \(.path)"' loot/*/unwrap.json | sort | uniq -c -w64 | sort -rn | head -40

# the same component version shipped everywhere?
jq -r '.components[] | "\(.component) \(.version)"' loot/*/sbom.json | sort | uniq -c | sort -rn | head
```

**A weakness in a shared updater, service or installer framework is a platform-scale finding**
for the same work as one product. Record the correlation in `references/hunt-memory.md` and say
so in the report — it changes both severity and the vendor's fix.
