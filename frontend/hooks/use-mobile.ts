import * as React from 'react'

const MOBILE_BREAKPOINT = 768
const QUERY = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`

function subscribe(callback: () => void) {
  const mql = window.matchMedia(QUERY)
  mql.addEventListener('change', callback)
  return () => mql.removeEventListener('change', callback)
}

function getSnapshot() {
  return window.matchMedia(QUERY).matches
}

function getServerSnapshot() {
  // No viewport on the server; default to desktop to avoid layout shift.
  return false
}

export function useIsMobile() {
  // useSyncExternalStore reads the current match on render and re-renders on
  // change without a synchronous setState-in-effect (React 19 purity rules).
  return React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)
}
