# Security audit: benhoyt/inih

Date: 2026-11-27 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 17 issue(s): 1 critical, 16 high.

## Findings

### 1. [HIGH] Integer overflow in size calculation

**CWE-190** | `tests/unittest_alloc.c` line 22

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
void* ini_realloc(void* ptr, size_t size) {
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 2. [HIGH] Use-after-free pattern

**CWE-416** | `tests/unittest_alloc.c` line 19

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(ptr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 3. [HIGH] Missing NULL check after allocation

**CWE-476** | `tests/unittest_alloc.c` line 13

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
printf("ini_malloc(%d)\n", (int)size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 4. [HIGH] Missing NULL check after allocation

**CWE-476** | `tests/unittest_alloc.c` line 14

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return malloc(size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 5. [HIGH] Missing NULL check after allocation

**CWE-476** | `tests/unittest_alloc.c` line 23

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
printf("ini_realloc(%d)\n", (int)size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 6. [HIGH] Missing NULL check after allocation

**CWE-476** | `tests/unittest_alloc.c` line 24

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return realloc(ptr, size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 7. [HIGH] Missing NULL check after allocation

**CWE-476** | `examples/ini_xmacros.c` line 27

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
strcmp(name, #n) == 0) cfg->s##_##n = strdup(value);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 8. [HIGH] Integer overflow in size calculation

**CWE-190** | `ini.c` line 30

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
void* ini_realloc(void* ptr, size_t size);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 9. [HIGH] Use-after-free pattern

**CWE-416** | `ini.c` line 153

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ini_free(line);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 10. [HIGH] Use-after-free pattern

**CWE-416** | `ini.c` line 266

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ini_free(line);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 11. [HIGH] Missing NULL check after allocation

**CWE-476** | `ini.c` line 28

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void* ini_malloc(size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 12. [HIGH] Missing NULL check after allocation

**CWE-476** | `ini.c` line 30

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
void* ini_realloc(void* ptr, size_t size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 13. [HIGH] Missing NULL check after allocation

**CWE-476** | `ini.c` line 129

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
line = (char*)ini_malloc(INI_INITIAL_ALLOC);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 14. [HIGH] Missing NULL check after allocation

**CWE-476** | `ini.c` line 151

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_line = ini_realloc(line, max_line);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 15. [HIGH] Missing NULL check after allocation

**CWE-476** | `examples/ini_example.c` line 24

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
pconfig->name = strdup(value);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 16. [HIGH] Missing NULL check after allocation

**CWE-476** | `examples/ini_example.c` line 26

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
pconfig->email = strdup(value);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 17. [CRITICAL] Format string vulnerability

**CWE-134** | `examples/ini_dump.c` line 26

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
printf("Usage: ini_dump filename.ini\n");
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---
