/** Dashboard figures describe real traffic, so simulator rows stay in the log but out of the numbers. */
export function realTraffic<T extends { simulated?: boolean }>(logs: T[]): T[] {
  return logs.filter((log) => !log.simulated);
}
