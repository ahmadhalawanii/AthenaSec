import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import QRCode from 'qrcode'

import { useDialog } from '../hooks/useDialog'
import type { IssuedCredentials } from '../types/adminStateTypes'

/*
  Live mode: the temporary password (and, for a new account, the two-factor
  setup) the backend issued. The backend does not keep either in clear, so this
  is the only time they can be seen; closing the dialog forgets them.
*/
function IssuedCredentialsModal({ issued, onClose }: { issued: IssuedCredentials; onClose: () => void }) {
  const dialogRef = useDialog(onClose)
  const [qr, setQr] = useState<string | null>(null)
  const [copied, setCopied] = useState('')
  const setupKey = issued.totpUri ? new URL(issued.totpUri).searchParams.get('secret') : null

  useEffect(() => {
    if (!issued.totpUri) {
      return undefined
    }

    let cancelled = false

    QRCode.toDataURL(issued.totpUri, { margin: 1, width: 200 })
      .then((url) => {
        if (!cancelled) {
          setQr(url)
        }
      })
      .catch(() => setQr(null))

    return () => {
      cancelled = true
    }
  }, [issued.totpUri])

  async function copy(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(label)
    } catch {
      setCopied('')
    }
  }

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <div ref={dialogRef} className="modal issued-credentials" role="dialog" aria-modal="true" aria-label="Sign-in details">
        <h2>Sign-in details for {issued.user.name}</h2>

        <div className="modal-body">
          <p className="sub">
            Give these to {issued.user.name} privately. They are shown only now; AthenaSec does not
            keep the password in a form anyone can read back.
          </p>

          <div className="issued-row">
            <span className="issued-label">Email</span>
            <code>{issued.user.email}</code>
          </div>

          {issued.temporaryPassword && (
            <div className="issued-row">
              <span className="issued-label">Temporary password</span>
              <code data-field="temporaryPassword">{issued.temporaryPassword}</code>
              <button className="btn small" type="button" onClick={() => copy('password', issued.temporaryPassword ?? '')}>
                {copied === 'password' ? 'Copied' : 'Copy'}
              </button>
            </div>
          )}

          {issued.temporaryPassword && (
            <p className="sub issued-step">
              They will be asked to choose their own password the first time they sign in with it.
            </p>
          )}

          {!issued.temporaryPassword && issued.totpUri && (
            <p className="sub issued-step">
              Their old authenticator entry no longer works and they have been signed out. Their
              password is unchanged.
            </p>
          )}

          {issued.totpUri && (
            <>
              <p className="sub issued-step">
                Two-factor sign-in: scan this with an authenticator app (Google Authenticator,
                Microsoft Authenticator, 1Password), or type the setup key.
              </p>
              <div className="issued-qr">
                {qr ? <img src={qr} width={200} height={200} alt="Two-factor setup QR code" /> : <span>Preparing QR code…</span>}
              </div>
              {setupKey && (
                <div className="issued-row">
                  <span className="issued-label">Setup key</span>
                  <code data-field="setupKey">{setupKey}</code>
                  <button className="btn small" type="button" onClick={() => copy('key', setupKey)}>
                    {copied === 'key' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              )}
            </>
          )}

          {!issued.totpUri && issued.temporaryPassword && (
            <p className="sub issued-step">
              Their two-factor app keeps working. They have been signed out everywhere and sign in
              again with this password.
            </p>
          )}
        </div>

        <div className="modal-actions">
          <button className="btn primary" type="button" onClick={onClose}>
            I have shared these
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export default IssuedCredentialsModal
