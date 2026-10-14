import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import ActionCatalogue from '../components/ActionCatalogue'
import AttemptSimulator from '../components/AttemptSimulator'
import PermissionsView from '../components/PermissionsView'
import Tabs from '../components/Tabs'

type View = 'permissions' | 'catalogue'

const SUBTITLES: Record<View, string> = {
  permissions:
    'The AthenaSec agent decides for itself how to respond to an alert. You decide what it is allowed to use. Whitelisted actions are available to it; blacklisted actions are blocked; anything not listed is denied.',
  catalogue: 'Every action the agent has, where each one stands in the response policy, and a way to try an attempt.',
}

/*
  Response Policies: the Permissions tab (the whitelist, blacklist and protected
  targets, edited as a draft) and the Action catalogue tab (every action, where
  it stands in the policy, and Simulate an attempt). The tab is in the address (?view=catalogue).
  The unsaved-changes line, Discard and Save sit beside the title: the page gives the
  Permissions view an empty slot there to draw them into.
*/
function ResponsePoliciesPage() {
  // The selected tab lives in the URL (?view=catalogue) so a link opens the right tab
  const [searchParams, setSearchParams] = useSearchParams()
  const view: View = searchParams.get('view') === 'catalogue' ? 'catalogue' : 'permissions'
  const [actionsSlot, setActionsSlot] = useState<HTMLElement | null>(null)

  function selectView(next: View) {
    setSearchParams(next === 'permissions' ? {} : { view: next }, { replace: true })
  }

  return (
    <section
      className="page active"
      data-page="response-policies"
      data-page-name="Response Policies"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Response Policies</h1>

          <p className="sub" id="policySummary">
            {SUBTITLES[view]}
          </p>
        </div>

        {view === 'permissions' && <div className="headline-actions perm-bar" ref={setActionsSlot} />}
      </div>

      <Tabs
        label="Response policy views"
        tabs={[
          { value: 'permissions' as const, label: 'Permissions' },
          { value: 'catalogue' as const, label: 'Action catalogue' },
        ]}
        value={view}
        onChange={selectView}
      >
        {view === 'catalogue' ? (
          <>
            <ActionCatalogue />
            <AttemptSimulator />
          </>
        ) : (
          <PermissionsView actionsSlot={actionsSlot} />
        )}
      </Tabs>
    </section>
  )
}

export default ResponsePoliciesPage
