import { Fragment } from 'react'

// RULE-001, USR-004, AUD-205, ...
const RECORD_ID = /\b([A-Z]{2,4}-\d{3})\b/

type IdTextProps = {
  children: string
}

/*
  Text that may contain record ids. Each id is kept on one line, so a
  narrow row wraps between words and never after the hyphen
  ("RULE-" / "001"). The text itself is unchanged.
*/
function IdText({ children }: IdTextProps) {
  return (
    <>
      {children.split(RECORD_ID).map((part, index) =>
        index % 2 === 1 ? (
          <span className="record-id" key={index}>
            {part}
          </span>
        ) : (
          <Fragment key={index}>{part}</Fragment>
        ),
      )}
    </>
  )
}

export default IdText
