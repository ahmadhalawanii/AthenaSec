import { useLiveData } from '../api/liveDataContext'

/*
  Live mode: a change the backend refused or could not save (closing an alert,
  saving a user...). The page has already put things back as they were; this
  says why, until it is dismissed.
*/
function LiveNotice() {
  const { notice, setNotice } = useLiveData()

  if (!notice) {
    return null
  }

  return (
    <div className="toast live-notice" role="alert">
      <span>{notice}</span>
      <button className="text-button" type="button" onClick={() => setNotice(null)}>
        Dismiss
      </button>
    </div>
  )
}

export default LiveNotice
