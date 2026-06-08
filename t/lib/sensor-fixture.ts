/** Shared sensor test fixture populated by sensor-community scenario, read by initiation scenarios. */

export interface SensorTestContext {
  communityName: string;
  communityUiEci: string;
  communityQueryEci: string;
  manifoldAppEci: string;
}

let context: Partial<SensorTestContext> = {};

export function setSensorTestContext(partial: Partial<SensorTestContext>): void {
  context = { ...context, ...partial };
}

export function getSensorTestContext(): SensorTestContext {
  const { communityName, communityUiEci, communityQueryEci, manifoldAppEci } = context;
  if (!communityName || !communityUiEci || !communityQueryEci || !manifoldAppEci) {
    throw new Error(
      "Sensor test context not initialized — sensor-community scenario must run first"
    );
  }
  return { communityName, communityUiEci, communityQueryEci, manifoldAppEci };
}
