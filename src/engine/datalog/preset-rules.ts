/**
 * sonobat — Datalog preset rules
 *
 * Predefined Datalog rule patterns for common penetration testing
 * analysis queries. These rules can be loaded by name and executed
 * against the fact base extracted from the database.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PresetRule {
  name: string;
  description: string;
  ruleText: string;
}

// ---------------------------------------------------------------------------
// Preset rule definitions
// ---------------------------------------------------------------------------

const PRESET_RULES: readonly PresetRule[] = [
  {
    name: 'reachable_services',
    description: 'Find all open services on each host with their port and application protocol.',
    ruleText: [
      'reachable(Host, Port, AppProto) :- service(Host, _, _, Port, AppProto, "open").',
      '?- reachable(Host, Port, AppProto).',
    ].join('\n'),
  },
  {
    name: 'authenticated_access',
    description: 'Services with discovered credentials, showing host, port, and username.',
    ruleText: [
      'auth_access(Host, Port, Username) :- service(Host, Svc, _, Port, _, "open"), credential(Svc, _, Username, _, _, _).',
      '?- auth_access(Host, Port, Username).',
    ].join('\n'),
  },
  {
    name: 'exploitable_endpoints',
    description:
      'HTTP endpoints with known vulnerabilities, including vulnerability type and severity.',
    ruleText: [
      'exploitable(Host, Port, Path, VulnType, Severity) :- service(Host, Svc, _, Port, _, _), http_endpoint(Svc, Ep, _, Path, _), vulnerability_endpoint(Vuln, Ep), vulnerability(Svc, Vuln, VulnType, _, Severity, _).',
      '?- exploitable(Host, Port, Path, VulnType, Severity).',
    ].join('\n'),
  },
  {
    name: 'critical_vulns',
    description: 'Critical severity vulnerabilities with host, port, title, and type.',
    ruleText: [
      'critical(Host, Port, Title, VulnType) :- service(Host, Svc, _, Port, _, _), vulnerability(Svc, _, VulnType, Title, "critical", _).',
      '?- critical(Host, Port, Title, VulnType).',
    ].join('\n'),
  },
  {
    name: 'attack_surface',
    description:
      'Full attack surface overview combining host, port, endpoint path, input name, and input location.',
    ruleText: [
      'surface(Host, Port, Path, InputName, Location) :- service(Host, Svc, _, Port, _, "open"), http_endpoint(Svc, Ep, _, Path, _), endpoint_input(Ep, Inp), input(Svc, Inp, Location, InputName).',
      '?- surface(Host, Port, Path, InputName, Location).',
    ].join('\n'),
  },
  {
    name: 'unfuzzed_inputs',
    description:
      'Inputs with observations but no associated vulnerability endpoint — candidates for fuzzing.',
    ruleText: [
      'unfuzzed(Host, Port, Path, InputName) :- service(Host, Svc, _, Port, _, "open"), http_endpoint(Svc, Ep, _, Path, _), endpoint_input(Ep, Inp), input(Svc, Inp, _, InputName), observation(Inp, _, _, _, _), not vulnerability_endpoint(_, Ep).',
      '?- unfuzzed(Host, Port, Path, InputName).',
    ].join('\n'),
  },
] as const;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Get all preset Datalog rules.
 *
 * @returns Array of all preset rules
 */
export function getPresetRules(): PresetRule[] {
  return [...PRESET_RULES];
}

/**
 * Get a specific preset rule by name.
 *
 * @param name - The preset rule name (e.g. 'reachable_services')
 * @returns The preset rule if found, undefined otherwise
 */
export function getPresetRule(name: string): PresetRule | undefined {
  return PRESET_RULES.find((r) => r.name === name);
}
