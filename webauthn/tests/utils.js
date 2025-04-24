// Helper function to run a test case
let testsFailed = 0;
const testResults = [];
let testsPassed = 0;
function runTest(description, testFn) {
    process.stdout.write(`Running: ${description}... `);
    try {
        testFn();
        process.stdout.write('PASS\n');
        testsPassed++;
        testResults.push({ description, status: 'PASS' });
    } catch (error) {
        process.stdout.write('FAIL\n');
        testsFailed++;
        testResults.push({ description, status: 'FAIL', error: error.stack });
        // Optionally log the full error immediately
        // console.error(`\\n[FAIL] ${description}\\n`, error);
    }
}

function getTestResults() {
    return {
        testsPassed,
        testsFailed,
        testResults
    };
}

function getTestSummary() {
    console.log('\\n--- Test Summary ---');
    if (testsFailed > 0) {
        console.error(`\x1b[31m${testsFailed} test(s) failed.\x1b[0m`);
        testResults.filter(r => r.status === 'FAIL').forEach(r => {
            console.error(`-------------------------------------`);
            console.error(`[FAIL] ${r.description}`);
            console.error(r.error);
        });
        console.error(`-------------------------------------`);
    } else {
        console.log(`\x1b[32mAll ${testsPassed} tests passed!\x1b[0m`);
    }
    console.log('--------------------');

    process.exit(testsFailed > 0 ? 1 : 0); 
}

module.exports = {
    runTest,
    getTestResults,
    getTestSummary
};