
## Findings Summary

### <a name="M-Unhandled 0 value may return incorrect result#198"></a> [M-01] Unhandled 0 value may return incorrect result

**Description**

write_prices function internally calling process_payload then write the values to storage.prices. But the aggregated_values may has 0 value after process_input -> values.median process, the write_prices() function directly write the values into the storage instead of filter the 0 price. So it may return 0 price to any users, may cause unexpected behaviours to the users.

**Recommendation**:

Filter the 0 price before writing to the storage.
