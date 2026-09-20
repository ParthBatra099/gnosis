import { useEffect, useRef, useState } from 'react';
import type { FormEvent, KeyboardEvent } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { askGnosis, isUnauthorizedError } from '../../api/assistant';
import '../../styles/ask-gnosis.css';

const MAX_QUERY_LENGTH = 500;

const EXAMPLE_QUESTIONS: string[] = [
  'What resources can I access?',
  'Show me my access requests',
  'What access grants do I have?',
  'Show me my profile',
];

type ExchangeStatus = 'pending' | 'success' | 'error';

interface Exchange {
  id: number;
  query: string;
  status: ExchangeStatus;
  answer: string;
  sources: string[];
  accessDenied: boolean;
}

export function AskGnosis() {
  const { logout } = useAuth();
  const [query, setQuery] = useState<string>('');
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const nextId = useRef<number>(0);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (exchanges.length === 0) return;
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, [exchanges]);

  async function submitQuestion() {
    if (isLoading) return;

    const trimmed = query.trim();
    if (!trimmed) {
      setValidationMessage('Enter a question to continue.');
      return;
    }

    const id = nextId.current;
    nextId.current += 1;

    setValidationMessage(null);
    setQuery('');
    setIsLoading(true);
    setExchanges((prev) => [
      ...prev,
      {
        id,
        query: trimmed,
        status: 'pending',
        answer: '',
        sources: [],
        accessDenied: false,
      },
    ]);

    try {
      const result = await askGnosis(trimmed);
      setExchanges((prev) =>
        prev.map((exchange) =>
          exchange.id === id
            ? {
                ...exchange,
                status: 'success',
                answer: result.answer,
                sources: result.sources,
                accessDenied: result.access_denied,
              }
            : exchange
        )
      );
    } catch (error) {
      const expired = isUnauthorizedError(error);
      setExchanges((prev) =>
        prev.map((exchange) =>
          exchange.id === id
            ? {
                ...exchange,
                status: 'error',
                answer: expired
                  ? 'Your session has expired. Please sign in again.'
                  : 'GNOSIS could not process your request. Please try again.',
              }
            : exchange
        )
      );
      if (expired) {
        logout();
      }
    } finally {
      setIsLoading(false);
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submitQuestion();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (
      event.key === 'Enter' &&
      !event.shiftKey &&
      !event.nativeEvent.isComposing
    ) {
      event.preventDefault();
      void submitQuestion();
    }
  }

  function handleExampleClick(example: string) {
    setQuery(example);
    setValidationMessage(null);
    inputRef.current?.focus();
  }

  return (
    <section className="gnosis-ask" aria-labelledby="gnosis-ask-title">
      <header className="gnosis-ask__header">
        <h1 id="gnosis-ask-title" className="gnosis-ask__title">
          ASK GNOSIS
        </h1>
        <p className="gnosis-ask__subtitle">
          Ask questions about your authorized GNOSIS information.
        </p>
      </header>

      <div
        className="gnosis-ask__transcript"
        role="log"
        aria-live="polite"
        aria-busy={isLoading}
      >
        {exchanges.length === 0 ? (
          <div className="gnosis-ask__empty">
            <p className="gnosis-ask__empty-text">
              No questions yet. Try one of these:
            </p>
            <div className="gnosis-ask__examples">
              {EXAMPLE_QUESTIONS.map((example) => (
                <button
                  key={example}
                  type="button"
                  className="gnosis-ask__example"
                  onClick={() => handleExampleClick(example)}
                >
                  {example}
                </button>
              ))}
            </div>
          </div>
        ) : (
          exchanges.map((exchange) => (
            <article key={exchange.id} className="gnosis-ask__exchange">
              <div className="gnosis-ask__message gnosis-ask__message--user">
                <span className="gnosis-ask__role">USER</span>
                <p className="gnosis-ask__text">{exchange.query}</p>
              </div>

              <div
                className={
                  'gnosis-ask__message' +
                  (exchange.status === 'error'
                    ? ' gnosis-ask__message--error'
                    : exchange.accessDenied
                      ? ' gnosis-ask__message--denied'
                      : '')
                }
              >
                <span className="gnosis-ask__role">GNOSIS</span>

                {exchange.status === 'pending' ? (
                  <p className="gnosis-ask__pending">
                    <span className="gnosis-ask__spinner" aria-hidden="true" />
                    Processing your question...
                  </p>
                ) : (
                  <>
                    <p
                      className="gnosis-ask__text"
                      role={exchange.status === 'error' ? 'alert' : undefined}
                    >
                      {exchange.answer}
                    </p>

                    {exchange.status === 'success' &&
                      exchange.sources.length > 0 && (
                        <div className="gnosis-ask__sources">
                          <span className="gnosis-ask__sources-label">
                            Sources
                          </span>
                          <ul className="gnosis-ask__source-list">
                            {exchange.sources.map((source, index) => (
                              <li
                                key={`${source}-${index}`}
                                className="gnosis-ask__source"
                              >
                                {source}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                  </>
                )}
              </div>
            </article>
          ))
        )}
        <div ref={endRef} />
      </div>

      <form className="gnosis-ask__composer" onSubmit={handleSubmit} noValidate>
        <label htmlFor="gnosis-ask-input" className="gnosis-ask__label">
          Your question
        </label>
        <textarea
          id="gnosis-ask-input"
          ref={inputRef}
          className="gnosis-ask__input"
          rows={3}
          maxLength={MAX_QUERY_LENGTH}
          value={query}
          placeholder="Ask about your resources, requests, grants or profile..."
          aria-describedby="gnosis-ask-help"
          onChange={(event) => {
            setQuery(event.target.value);
            if (validationMessage) setValidationMessage(null);
          }}
          onKeyDown={handleKeyDown}
        />
        <div className="gnosis-ask__footer">
          <span
            id="gnosis-ask-help"
            className={
              'gnosis-ask__help' +
              (validationMessage ? ' gnosis-ask__help--error' : '')
            }
            role={validationMessage ? 'alert' : undefined}
          >
            {validationMessage ??
              `Enter to send, Shift+Enter for a new line. ${query.length}/${MAX_QUERY_LENGTH}`}
          </span>
          <button
            type="submit"
            className="gnosis-ask__submit"
            disabled={isLoading}
          >
            {isLoading ? 'Asking...' : 'Ask GNOSIS'}
          </button>
        </div>
      </form>
    </section>
  );
}