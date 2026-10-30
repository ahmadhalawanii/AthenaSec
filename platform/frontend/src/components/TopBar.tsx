import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { ROLE_LABELS } from '../data/appData'
import { notificationsFor } from '../data/notificationsData'
import { searchRecords } from '../data/searchIndex'
import {
  getSystemStatus,
} from '../data/statusSummary'
import type {
  SearchNavigationState,
  SearchResult,
} from '../types/searchTypes'
import { useAdminState } from '../hooks/useAdminState'
import { PHONE_QUERY, useMediaQuery } from '../hooks/useMediaQuery'
import { useResponseState } from '../hooks/useResponseState'
import { useSocState } from '../hooks/useSocState'
import { initialsOf } from '../utils/initials'

import BrandMark from './BrandMark'

// Cortex execution controls must be authorized, confirmed and audited by the backend.
// The existing /api/v1/runtime/control endpoint needs a secret operator key;
// NEVER embed that key in client-side JavaScript. Until an authenticated browser
// endpoint exists, this control remains visibly unavailable and does nothing.
function EmergencyKillSwitch() {
  return (
    <button
      className="emergency-kill-switch"
      type="button"
      disabled
      aria-label="Kill switch unavailable. Secure backend connection required to control Cortex execution."
      title="Kill switch unavailable until secure backend integration is complete"
    >
      <svg
        className="emergency-kill-icon"
        width="18"
        height="18"
        viewBox="0 0 24 24"
        aria-hidden="true"
        focusable="false"
      >
        <path d="M12 2v10M6.4 5.8a9 9 0 1 0 11.2 0" />
      </svg>
      <span className="emergency-kill-name">Kill Switch</span>
      <span className="emergency-kill-state">Not connected</span>
    </button>
  )
}

const SEARCH_LISTBOX_ID = 'globalSearchResults'
const searchOptionId = (index: number) => `globalSearchOption-${index}`

type TopBarProps = {
  userName: string
  role: 'Analyst' | 'Administrator'
  onLogout: () => void
  // True while the phone menu drawer is open: nothing in the bar can be reached behind it
  inert?: boolean
}

function TopBar({
  userName,
  role,
  onLogout,
  inert = false,
}: TopBarProps) {
  const routerNavigate = useNavigate()
  // On phones the bell and the account menu are on the first row, above the search box, so they come first in Tab order too
  const phone = useMediaQuery(PHONE_QUERY)
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Follows analyst actions (close, reopen, assign) made anywhere in the app
  const { alerts, executions, cases, approvals } = useSocState()
  const { now, actor } = useResponseState()
  // Follows admin changes (service checks, policies, users…) the same way
  const adminState = useAdminState()
  const systemStatus = getSystemStatus(adminState.services)
  const accountButtonRef = useRef<HTMLButtonElement>(null)

  const userInitials = initialsOf(userName)

  const roleLabel = ROLE_LABELS[role]

  const notifications = notificationsFor(role, approvals, now, actor?.id ?? '', adminState.auditLogs)

  const [notificationOpen, setNotificationOpen] =
    useState(false)

  const [userMenuOpen, setUserMenuOpen] =
    useState(false)

  function openNotifications() {
    setNotificationOpen(!notificationOpen)
    setUserMenuOpen(false)
  }

  function openUserMenu() {
    setUserMenuOpen(!userMenuOpen)
    setNotificationOpen(false)
  }

  function navigate(page: string, highlight?: string, view?: string) {
    setNotificationOpen(false)
    setUserMenuOpen(false)
    routerNavigate(`/app/${page}${view ? `?view=${view}` : ''}`, highlight ? { state: { highlight } } : undefined)
  }

  /*
    Close the menu before the logout dialog opens. Focus moves to the
    account button first: the dialog returns focus to whatever had it
    when it opened, and the Logout item is about to unmount.
  */
  function confirmLogout() {
    accountButtonRef.current?.focus()
    setUserMenuOpen(false)
    onLogout()
  }

  /*
    An open menu closes when Tab (or Shift+Tab) takes focus out of it, so focus
    never moves on into the page with the menu still open over it.
  */
  function closeMenuOnTabOut(event: KeyboardEvent<HTMLDivElement>, close: () => void) {
    if (event.key !== 'Tab') {
      return
    }

    const stops = [...event.currentTarget.querySelectorAll<HTMLElement>('button')]
    const index = stops.indexOf(document.activeElement as HTMLElement)

    if (index >= 0 && ((!event.shiftKey && index === stops.length - 1) || (event.shiftKey && index === 0))) {
      close()
    }
  }

  /*
    The app's only search shortcut: Ctrl+K / Cmd+K from anywhere, and
    "/" when not typing in a field. Dialogs keep the keyboard to
    themselves, so neither fires while one is open.
  */
  useEffect(() => {
    function handleShortcut(event: globalThis.KeyboardEvent) {
      if (document.querySelector('[role="dialog"]')) {
        return
      }

      const target = event.target
      const typing =
        target instanceof HTMLElement &&
        (target.isContentEditable ||
          ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))

      const commandK =
        (event.ctrlKey || event.metaKey) &&
        !event.altKey &&
        !event.shiftKey &&
        event.key.toLowerCase() === 'k'

      const slash =
        event.key === '/' &&
        !event.ctrlKey &&
        !event.metaKey &&
        !event.altKey &&
        !typing

      if (!commandK && !slash) {
        return
      }

      event.preventDefault()
      setNotificationOpen(false)
      setUserMenuOpen(false)
      searchInputRef.current?.focus()
      searchInputRef.current?.select()
    }

    document.addEventListener('keydown', handleShortcut)

    return () =>
      document.removeEventListener('keydown', handleShortcut)
  }, [])

  const [searchQuery, setSearchQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [activeResult, setActiveResult] = useState(0)

  // Current records on both sides, so results show this session's changes
  const { responsePolicy, users, auditLogs, services } = adminState
  const searchResults = useMemo(
    () =>
      searchRecords(
        role,
        searchQuery,
        { alerts, executions, cases, approvals },
        { responsePolicy, users, auditLogs, services },
      ),
    [role, searchQuery, alerts, executions, cases, approvals, responsePolicy, users, auditLogs, services],
  )

  const showResults = searchOpen && searchQuery.trim() !== ''

  // Results arrive in index order, so consecutive runs share a page.
  const searchGroups = useMemo(() => {
    const groups: Array<{
      page: string
      label: string
      items: Array<{ result: SearchResult; index: number }>
    }> = []

    searchResults.forEach((result, index) => {
      const last = groups[groups.length - 1]

      if (last && last.page === result.page) {
        last.items.push({ result, index })
      } else {
        groups.push({
          page: result.page,
          label: result.pageLabel,
          items: [{ result, index }],
        })
      }
    })

    return groups
  }, [searchResults])

  function updateSearch(value: string) {
    setSearchQuery(value)
    setActiveResult(0)
    setSearchOpen(true)
    setNotificationOpen(false)
    setUserMenuOpen(false)
  }

  function openResult(result: SearchResult) {
    const state: SearchNavigationState = { highlight: result.id }

    setSearchQuery('')
    setSearchOpen(false)
    routerNavigate(`/app/${result.page}${result.view ? `?view=${result.view}` : ''}`, { state })
  }

  function handleSearchKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Escape') {
      if (showResults) {
        event.preventDefault()
        setSearchOpen(false)
      }
      return
    }

    if (!showResults || searchResults.length === 0) {
      return
    }

    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActiveResult((index) => (index + 1) % searchResults.length)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActiveResult(
        (index) =>
          (index - 1 + searchResults.length) % searchResults.length,
      )
    } else if (event.key === 'Enter') {
      event.preventDefault()
      openResult(searchResults[activeResult] ?? searchResults[0])
    }
  }

  const searchPlaceholder =
    role === 'Administrator'
      ? 'Search policies, users, logs…'
      : 'Search alerts, IPs, endpoints…'

  // The bell and the account menu (drawn at the right, and on phones on the first row)
  const actions = (
    <div className="top-actions">
      <div
        className="dropdown-wrap"
        onKeyDown={(event) => closeMenuOnTabOut(event, () => setNotificationOpen(false))}
      >
        <button
          className="icon-btn"
          type="button"
          onClick={openNotifications}
          aria-label={`Notifications, ${notifications.length} unread`}
          aria-haspopup="true"
          aria-expanded={notificationOpen}
        >
          <svg
            className="bell-icon"
            width="18"
            height="18"
            viewBox="0 0 24 24"
            aria-hidden="true"
            focusable="false"
          >
            <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
            <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
          </svg>
          {notifications.length > 0 && (
            <span className="badge-dot" aria-hidden="true" />
          )}
        </button>

        {notificationOpen && (
          <div className="dropdown">
            {notifications.map((item) => (
              <button
                key={item.id}
                className="drop-item"
                onClick={() => navigate(item.page, item.highlight, item.view)}
              >
                <strong>{item.title}</strong>
                <p>{item.detail}</p>
              </button>
            ))}
          </div>
        )}
      </div>

      <div
        className="dropdown-wrap"
        onKeyDown={(event) => closeMenuOnTabOut(event, () => setUserMenuOpen(false))}
      >
        <button
          ref={accountButtonRef}
          className="user-avatar"
          type="button"
          onClick={openUserMenu}
          aria-label={`Account menu for ${userName}`}
          aria-haspopup="true"
          aria-expanded={userMenuOpen}
        >
          <span className="user-initials" aria-hidden="true">
            {userInitials}
          </span>
          <span className="user-meta" aria-hidden="true">
            <span className="user-name">{userName}</span>
            <span className="user-role">{roleLabel}</span>
          </span>
        </button>

        {userMenuOpen && (
          <div className="dropdown">
            <button
              className="drop-item"
              onClick={() => navigate('profile')}
            >
              <strong>Profile</strong>
            </button>

            {role === 'Administrator' && (
              <button
                className="drop-item"
                onClick={() => navigate('settings')}
              >
                <strong>Settings</strong>
              </button>
            )}

            <button
              className="drop-item"
              onClick={confirmLogout}
            >
              <strong>Logout</strong>
            </button>
          </div>
        )}
      </div>
    </div>
  )

  return (
    <div className="topbar" inert={inert}>
      <button
        className="logo"
        type="button"
        onClick={() => navigate('dashboard')}
      >
        <BrandMark />
        <span className="logo-word">AthenaSec</span>
      </button>

      {phone && actions}

      {/*
        System status, kill switch and search share a row on phones, which
        scrolls away under the sticky first row (see .topbar-search in
        athenasec.css). Elsewhere this wrapper has no box of its own.
      */}
      <div className="topbar-search">
        <div
          className={`system-health-meter ${systemStatus.level}`}
          role="status"
          aria-label={`System status: ${systemStatus.title}. ${systemStatus.text}`}
          title={systemStatus.text}
        >
          <span className="system-health-icon" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" focusable="false">
              <path d="M3 12h4l3-6 4 12 3-6h4" />
            </svg>
          </span>
          {role === 'Administrator' ? (
            <Link className="system-health-copy" to="/app/service-panel?view=health">
              <span className="system-health-caption">System status</span>
              <strong className="system-health-label">{systemStatus.title}</strong>
            </Link>
          ) : (
            <span className="system-health-copy">
              <span className="system-health-caption">System status</span>
              <strong className="system-health-label">{systemStatus.title}</strong>
            </span>
          )}
        </div>

        <EmergencyKillSwitch />

        <div className="search-wrap">
          <svg
            className="search-icon"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            aria-hidden="true"
            focusable="false"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="m20 20-3.5-3.5" />
          </svg>

          <input
            ref={searchInputRef}
            className="search-input"
            id="globalSearch"
            name="globalSearch"
            type="search"
            role="combobox"
            aria-label={searchPlaceholder.replace('…', '')}
            aria-autocomplete="list"
            aria-expanded={showResults}
            aria-controls={SEARCH_LISTBOX_ID}
            aria-keyshortcuts="Control+K Meta+K /"
            aria-activedescendant={
              showResults && searchResults.length > 0
                ? searchOptionId(activeResult)
                : undefined
            }
            autoComplete="off"
            spellCheck={false}
            placeholder={searchPlaceholder}
            value={searchQuery}
            onChange={(event) => updateSearch(event.target.value)}
            onFocus={() => setSearchOpen(true)}
            onBlur={() => setSearchOpen(false)}
            onKeyDown={handleSearchKeyDown}
          />

          <kbd className="search-kbd" aria-hidden="true">
            Ctrl K
          </kbd>

          {showResults && (
            <div
              className="search-results"
              id={SEARCH_LISTBOX_ID}
              role="listbox"
              aria-label="Search results"
            >
              {searchResults.length === 0 ? (
                <p className="search-empty" role="status">
                  No matches for “{searchQuery.trim()}”
                </p>
              ) : (
                searchGroups.map((group) => (
                  <div
                    key={group.page}
                    role="group"
                    aria-label={group.label}
                  >
                    <div className="search-group" aria-hidden="true">
                      {group.label}
                    </div>

                    {group.items.map(({ result, index }) => (
                      <div
                        key={result.id}
                        className={
                          index === activeResult
                            ? 'search-result active'
                            : 'search-result'
                        }
                        id={searchOptionId(index)}
                        role="option"
                        aria-selected={index === activeResult}
                        onMouseDown={(event) => event.preventDefault()}
                        onMouseEnter={() => setActiveResult(index)}
                        onClick={() => openResult(result)}
                      >
                        <strong>{result.title}</strong>
                        <p>{result.detail}</p>
                      </div>
                    ))}
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      {!phone && actions}
    </div>
  )
}

export default TopBar
