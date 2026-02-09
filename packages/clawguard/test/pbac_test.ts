
import { PolicyEvaluator, ActionRequest } from '../dist/policy/evaluator.js';
import { strict as assert } from 'node:assert';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

// Fix 2: ESM-safe policy path resolution
// ../policy.yaml relative to this test file
const currentDir = dirname(fileURLToPath(import.meta.url));
const policyPath = resolve(currentDir, '../policy.yaml');

console.log(`🧪 Testing PBAC Policy Evaluator with policy: ${policyPath}`);
const evaluator = new PolicyEvaluator(policyPath);

// Test 1: Untrusted Source -> Needs Approval
{
    console.log('Test 1: Untrusted source match -> needs_approval');
    const request: ActionRequest = {
        tool: 'shell',
        action: 'exec',
        args: { command: 'ls -la' },
        untrustedSource: 'web'
    };
    const result = evaluator.evaluate(request);
    assert.equal(result.decision, 'needs_approval', 'Should require approval for web source');
    // Stronger Assertion: Check reason contains expected keyword (reduces flakiness vs exact string)
    assert.ok(result.reason?.toLowerCase().includes('approval'), 'Reason should mention approval requirement');
    console.log('✅ Passed');
}

// Test 2: Trusted Source -> Allow
{
    console.log('Test 2: Trusted source matches "ls *" -> allow');
    const request: ActionRequest = {
        tool: 'shell',
        action: 'exec',
        args: { command: 'ls -la' }
        // No untrustedSource
    };
    const result = evaluator.evaluate(request);
    assert.equal(result.decision, 'allow', 'Should allow trusted ls -la');
    console.log('✅ Passed');
}

// Test 3: Precedence (rm -rf /) -> Deny
{
    console.log('Test 3: "rm -rf /" matches deny match -> deny (even if untrusted match needs_approval)');
    const request: ActionRequest = {
        tool: 'shell',
        action: 'exec',
        args: { command: 'rm -rf /' },
        untrustedSource: 'web'
    };
    const result = evaluator.evaluate(request);
    assert.equal(result.decision, 'deny', 'Should deny rm -rf / explicitly');
    console.log('✅ Passed');
}

// Test 4: Interpreter Bypass -> Deny (Specific Rule)
{
    console.log('Test 4: "bash -c ..." matches deny match -> deny');
    const request: ActionRequest = {
        tool: 'shell',
        action: 'exec',
        args: { command: 'bash -c "rm -rf /"' }
    };
    const result = evaluator.evaluate(request);
    assert.equal(result.decision, 'deny', 'Should deny bash -c bypass');
    // Stronger Assertion: Confirm it hit the specific deny rule, not just default deny
    assert.ok(result.reason?.toLowerCase().includes('bypass'), 'Reason should mention bypass restriction');
    assert.equal(result.matchedRule?.pattern, 'bash -c *', 'Should match specific interpreter deny rule');
    console.log('✅ Passed');
}

// Test 5: Whitespace Regression (Deterministic) -> Deny (Default)
{
    console.log('Test 5: "bash   -c ..." (explicit spaces) -> deny');
    const request: ActionRequest = {
        tool: 'shell',
        action: 'exec',
        // Make whitespace explicit to avoid invisible editor normalization
        args: { command: 'bash' + ' '.repeat(3) + '-c "echo bypass"' }
    };
    const result = evaluator.evaluate(request);

    // We expect DENY.
    // If pattern "bash -c *" is strict on single space, it won't match the rule.
    // However, it falls through to default DENY because NO allow rule matches.
    assert.equal(result.decision, 'deny', 'Should be denied (default deny catches mismatches)');
    // Confirm it's hitting default deny (matchedRule is undefined)
    assert.equal(result.matchedRule, undefined, 'Should hit default deny for mismatched pattern variants');
    console.log('✅ Passed');
}

// Test 6: Unknown Command -> Deny (Default)
{
    console.log('Test 6: Unknown command -> default deny');
    const request: ActionRequest = {
        tool: 'shell',
        action: 'exec',
        args: { command: 'unknown_command_xyz' }
    };
    const result = evaluator.evaluate(request);
    assert.equal(result.decision, 'deny', 'Should default to deny');
    console.log('✅ Passed');
}

console.log('🎉 All PBAC tests passed!');
