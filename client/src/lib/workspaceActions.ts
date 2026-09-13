export type WorkspaceView =
  | "dashboard"
  | "analyzer"
  | "intelligence"
  | "geolocation"
  | "forensics"
  | "assistant"
  | "reports"
  | "settings"
  | "requirements";

export function requirementTarget(action?: WorkspaceView): WorkspaceView {
  return action ?? "settings";
}

export function reportSuccessMessage(format: "csv" | "pdf") {
  return `${format.toUpperCase()} report downloaded from saved case evidence.`;
}

export function signedOutMode(): "landing" {
  return "landing";
}

export function nextMobileOpenState(isOpen: boolean) {
  return !isOpen;
}
