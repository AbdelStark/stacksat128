# STACKSAT-128 Bitcoin Script Implementation Execution Plan

## Overview

This document outlines the detailed execution plan for implementing a fully functioning STACKSAT-128 hash function in Bitcoin Script. The plan addresses the specific issues encountered with the current implementation and provides a step-by-step approach to achieving a complete solution.

## Current Issues

Our current implementation faces the following issues:

1. **StackTracker Framework Limitations**
   - The `OP_TOALTSTACK` and `OP_FROMALTSTACK` operations fail in the StackTracker framework.
   - This prevents non-empty message processing from working correctly.

2. **Complex Stack Management**
   - State transfer between algorithm phases causes stack organization issues.
   - Deep stack operations are difficult to manage with StackTracker.

3. **Working Implementation Scope**
   - Empty message case works correctly (proving algorithm correctness).
   - Non-empty messages fail consistently at the same point.

## Execution Plan

### Stage 1: Direct Bitcoin Script Implementation (2 weeks)

#### Week 1: Core Functions and Basic Structure

1. **Create Direct Script Functions**
   - Implement `add16` modulo addition directly with opcodes
   - Create S-box lookup table mechanism without StackTracker
   - Implement basic state management without altstack

2. **Test Basic Building Blocks**
   - Unit test the modulo addition function
   - Test S-box lookups independently
   - Verify state initialization and access

3. **Message Padding Implementation**
   - Implement message padding for empty message
   - Test with single-block message padding
   - Validate padding output format

#### Week 2: Core Algorithm Direct Implementation

1. **Implement Core Algorithm Phases**
   - Substitution phase (SubNibbles)
   - Permutation phase (PermuteNibbles)
   - Mixing phase (MixColumns)
   - Round constant addition (AddConstant)

2. **State Management**
   - Design clear stack management approach without altstack
   - Optimize operations to minimize stack depth
   - Document stack layout and transformations

3. **Debugging Infrastructure**
   - Add stack debug output at key checkpoints
   - Implement comparison with reference implementation
   - Create verbose diagnostic output

### Stage 2: Integration and Testing (1 week)

1. **End-to-End Testing**
   - Empty message test
   - 15-byte message (single block)
   - 32-byte message (two blocks)
   - Standard test vector ("quick brown fox...")

2. **Edge Case Testing**
   - Messages of varying lengths
   - Messages requiring complex padding
   - Stress testing with large inputs

3. **Performance Testing**
   - Script size optimization
   - Stack depth analysis
   - Execution step count optimization

### Stage 3: Optimization and Finalization (1 week)

1. **Script Size Optimization**
   - Consolidate repeated operations
   - Optimize state transformations
   - Minimize redundant stack operations

2. **Performance Optimization**
   - Optimize critical paths in the algorithm
   - Reduce unnecessary stack movements
   - Improve S-box lookup efficiency

3. **Documentation and Examples**
   - Create comprehensive algorithm documentation
   - Provide usage examples
   - Add test vectors and verification cases

## Implementation Strategy Details

### Direct Bitcoin Script Approach

To avoid StackTracker limitations, we'll implement the algorithm directly in Bitcoin Script:

1. **Stack Layout Design**
   ```
   [message_nibbles] [state_nibbles] [sbox_table]
   ```

2. **State Access Pattern**
   - Use direct OP_PICK operations for state access
   - Maintain consistent stack layout throughout
   - Use standardized stack cleanup after operations

3. **S-box Lookup**
   ```
   // Get nibble value
   <depth> OP_PICK
   
   // Convert to S-box index (15 - value)
   <15> OP_SWAP OP_SUB
   
   // Calculate S-box table position
   <sbox_table_depth> OP_ADD
   
   // Get S-box value
   OP_PICK
   ```

4. **Modulo 16 Addition**
   ```
   OP_ADD
   <16> OP_2DUP OP_GREATERTHANOREQUAL
   OP_IF
       OP_SUB
   OP_ELSE
       OP_DROP
   OP_ENDIF
   ```

### Permutation Implementation

The permutation phase will be implemented directly with a sequence of PICK operations:

```
// For each output position
for dest_idx in 0..64:
    // Calculate source based on STACKSATSCRIPT_INV_FINAL_PERM
    source_idx = STACKSATSCRIPT_INV_FINAL_PERM[dest_idx]
    
    // PICK the source value from appropriate stack depth
    <calculated_depth> OP_PICK
```

### State Management During Absorption

To absorb message blocks without using altstack:

```
// For each rate nibble (0 to 31)
for i in 0..32:
    // Get message nibble
    <msg_depth> OP_PICK
    
    // Get current state nibble
    <state_depth> OP_PICK
    
    // Add modulo 16
    ... add16 operation ...
    
    // Result now on top of stack
```

### Cleanup Strategy

After each round, the following cleanup is needed:

```
// For items to preserve (S-box, etc.)
<deep_item_depth> OP_PICK  // Move to top
...

// Then drop used items
for _ in 0..items_to_drop:
    OP_DROP
```

## Milestones and Deliverables

| Week | Milestone | Deliverables |
|------|-----------|--------------|
| 1.1  | Core Direct Script Functions | - Working add16 modulo function<br>- S-box lookup mechanism<br>- Test cases for basic operations |
| 1.2  | Message Processing | - Padding implementation<br>- State initialization<br>- Block processing structure |
| 2.1  | Core Algorithm Implementation | - SubNibbles operation<br>- PermuteNibbles operation<br>- MixColumns operation<br>- AddConstant operation |
| 2.2  | Full Integration | - Working end-to-end implementation<br>- Test with empty message<br>- Test with single block message |
| 3.1  | Testing and Optimization | - Comprehensive test suite<br>- Standard vector verification<br>- Performance optimizations |
| 3.2  | Final Delivery | - Complete documented implementation<br>- Example usage code<br>- Performance benchmarks |

## Risk Management

| Risk | Mitigation Strategy |
|------|---------------------|
| Bitcoin Script stack limits | Optimize stack usage, monitor depth, subdivide operations |
| Script size constraints | Minimize duplication, optimize for size, modularize operations |
| Complex permutation patterns | Use precomputed lookup tables, optimize access patterns |
| Testing complexity | Build incremental test infrastructure, validate against reference |

## Success Criteria

The implementation will be considered successful when:

1. All test vectors produce correct hashes matching the reference implementation
2. The script executes efficiently within Bitcoin's constraints
3. The implementation is well-documented with clear usage examples
4. All edge cases are handled correctly

## Conclusion

This execution plan provides a comprehensive approach to implementing STACKSAT-128 in Bitcoin Script by addressing the current limitations and creating a direct implementation. By focusing on clear stack management and incremental testing, the plan offers a path to a fully functioning implementation within 4 weeks.