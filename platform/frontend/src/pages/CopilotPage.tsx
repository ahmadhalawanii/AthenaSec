import CopilotChat from '../components/CopilotChat'

type CopilotPageProps = {
  role: 'Analyst' | 'Administrator'
  // False in demo mode: there is no backend to ask
  live: boolean
}

function CopilotPage({ role, live }: CopilotPageProps) {
  return (
    <section className="page active" data-page="copilot" data-page-name="Security Copilot">
      <div className="headline">
        <div>
          <h1>Security Copilot</h1>
          <p className="sub">
            Ask about alerts, cases and what AthenaSec has done. It reads stored records and
            cannot block, approve or change anything.
          </p>
        </div>
      </div>

      <div className="card">
        <CopilotChat role={role} live={live} />
      </div>
    </section>
  )
}

export default CopilotPage
