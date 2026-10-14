/*
  Sidebar icon outlines (24-unit grid, drawn as a 1.8 stroke) from
  the approved design, design/athenasec-redesign/screens/Nav.dc.html.
*/
export const NAV_ICONS = {
  ops: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18zM12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8zM12 1v4M12 19v4M1 12h4M19 12h4',
  alerts: 'M12 3 2.5 20h19L12 3zM12 10v4M12 17.5v.01',
  cases: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z',
  response: 'M13 2 4 14h7l-1 8 9-12h-7l1-8z',
  // Approvals: a shield with a tick
  approvals: 'M12 3 4 6v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V6l-8-3zM8.5 12l2.5 2.5L15.5 9.5',
  home: 'M3 11 12 4l9 7v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z',
  config: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4',
  policies: 'M6 3v12M6 15a3 3 0 1 0 0 6a3 3 0 1 0 0-6zM18 9a3 3 0 1 0 0-6a3 3 0 1 0 0 6zM18 9c0 6-12 3-12 6',
  users: 'M9 11a4 4 0 1 0 0-8a4 4 0 1 0 0 8zM2 21a7 7 0 0 1 14 0M17 11a3 3 0 1 0 0-6M22 21a6 6 0 0 0-4-5.7',
  audit: 'M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h7',
  // Service Panel: a rack of two servers with status lights
  panel: 'M4 4h16a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zM4 13h16a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1zM7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6',
  settings: 'M12 15a3 3 0 1 0 0-6a3 3 0 1 0 0 6zM12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1',
} as const

export type NavIconName = keyof typeof NAV_ICONS
