import type { McpActionType } from '@/types/governance';

/** Dashboard figures describe real traffic, so simulator rows stay in the log but out of the numbers. */
export function realTraffic<T extends { simulated?: boolean }>(logs: T[]): T[] {
  return logs.filter((log) => !log.simulated);
}

/** Matches the name the server logs when none is sent, so the form and the log agree. */
export const DEFAULT_SIMULATED_USERNAME = 'test-user';

export interface SimulatedCall {
  profileId: string;
  username: string;
  toolName: McpActionType;
  targetObject: string;
}

/** Sample traffic for local testing. The names are synthetic so nobody reads them as real people. */
export function trafficBurstCalls(profileIds: string[]): SimulatedCall[] {
  const profileAt = (idx: number, fallback: string) => profileIds[idx] || profileIds[0] || fallback;
  return [
    {
      profileId: profileAt(0, '00e5g000001A9xLAAS'),
      username: 'test-user-1',
      toolName: 'soql_query',
      targetObject: 'Opportunity',
    },
    {
      profileId: profileAt(1, '00e5g000001B2k9AAC'),
      username: 'test-user-2',
      toolName: 'update_record',
      targetObject: 'Account',
    },
    {
      profileId: profileAt(2, '00e5g000001D8pRAAU'),
      username: 'test-user-3',
      toolName: 'get_record',
      targetObject: 'Case',
    },
    {
      profileId: profileAt(1, '00e5g000001B2k9AAC'),
      username: 'test-user-4',
      toolName: 'delete_record',
      targetObject: 'Account',
    },
    {
      profileId: profileAt(3, '00e5g000001C4mQAAQ'),
      username: 'test-user-5',
      toolName: 'describe_object',
      targetObject: 'Opportunity',
    },
    {
      profileId: profileIds[profileIds.length - 1] || '00e5g000001J0yVAAS',
      username: 'test-user-6',
      toolName: 'soql_query',
      targetObject: 'Contact',
    },
  ];
}
