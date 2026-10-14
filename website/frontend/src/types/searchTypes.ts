export type SearchResult = {
  id: string
  page: string
  // The page's tab to open (written as ?view=), e.g. 'health' on the Service Panel
  view?: string
  pageLabel: string
  title: string
  detail: string
  keywords: string
}

export type SearchNavigationState = {
  highlight?: string
}
