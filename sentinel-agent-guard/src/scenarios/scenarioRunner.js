import { SCENARIO_DEFINITIONS } from './testDatasets.js';

export class ScenarioRunner {
  constructor({ simulatedAgent, auditLogger }) {
    this.agent = simulatedAgent;
    this.auditLogger = auditLogger;
  }

  getScenarios() {
    return SCENARIO_DEFINITIONS;
  }

  async runScenario(scenarioId) {
    const scenario = SCENARIO_DEFINITIONS.find(s => s.id === scenarioId);
    if (!scenario) {
      throw new Error(`Scenario '${scenarioId}' not found.`);
    }

    const startTime = Date.now();
    const result = await this.agent.run({
      userPrompt: scenario.userPrompt,
      agentRole: scenario.agentRole,
      forcedScenarioId: scenario.id
    });
    const durationMs = Date.now() - startTime;

    // Verify whether the scenario met its expected security objective
    const passed = (result.verdict === 'ALLOW' && scenario.expectedDecisions.every(d => d.expectedDecision === 'ALLOW'))
      || (result.verdict === 'DENY' && scenario.expectedDecisions.some(d => d.expectedDecision === 'DENY'))
      || (result.verdict === 'REQUIRE_APPROVAL' && scenario.expectedDecisions.some(d => d.expectedDecision === 'REQUIRE_APPROVAL'));

    return {
      scenarioId: scenario.id,
      title: scenario.title,
      category: scenario.category,
      passed,
      durationMs,
      agentResult: result
    };
  }

  async runAllScenarios() {
    const results = [];
    for (const s of SCENARIO_DEFINITIONS) {
      const res = await this.runScenario(s.id);
      results.push(res);
    }
    return results;
  }
}
