import type { ActivationPreparation } from '../api/authConfiguration'

export type ActivationConfirmation = {
  reason: string
  transitionSeconds: number
  acknowledgeReauthentication: boolean
  acknowledgeEmergencyRecovery: boolean
}

export const emptyActivationConfirmation: ActivationConfirmation = {
  reason: '', transitionSeconds: 0, acknowledgeReauthentication: false, acknowledgeEmergencyRecovery: false,
}

export function validReason(value: string) {
  const reason = value.trim()
  return reason.length >= 8 && reason.length <= 512 && ![...reason].some((character) => {
    const code = character.charCodeAt(0)
    return code < 32 || code === 127
  })
}

export function validActivationConfirmation(value: ActivationConfirmation, preparation: ActivationPreparation, expired: boolean) {
  return !expired && validReason(value.reason) && value.transitionSeconds >= 0 &&
    value.transitionSeconds <= preparation.maximum_transition_seconds &&
    (!preparation.requires_reauthentication || (value.transitionSeconds === 0 && value.acknowledgeReauthentication && value.acknowledgeEmergencyRecovery))
}
