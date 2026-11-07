import { useEffect, useRef, useState } from 'react';
import type {
  FormEvent,
  KeyboardEvent,
} from 'react';

import {
  ArrowUp,
  BookOpen,
  Clock3,
  Copy,
  FileText,
  MessageSquare,
  Plus,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  User,
} from 'lucide-react';

import { useAuth } from '../../hooks/useAuth';

import {
  askGnosis,
  isUnauthorizedError,
} from '../../api/assistant';

import '../../styles/ask-gnosis.css';


/* =========================================================
   CONSTANTS
   ========================================================= */

const MAX_QUERY_LENGTH = 500;


/* =========================================================
   QUICK QUESTIONS
   ========================================================= */

/* =========================================================
   TYPES
   ========================================================= */

type ExchangeStatus =
  | 'pending'
  | 'success'
  | 'error';

interface Exchange {
  id: number;
  query: string;
  answer: string;
  sources: string[];
  status: ExchangeStatus;
  accessDenied: boolean;
}


/* =========================================================
   COMPONENT
   ========================================================= */

export function AskGnosis() {

  const {
    user,
    logout,
  } = useAuth();


  /* =======================================================
     STATE
     ======================================================= */

  const [query, setQuery] =
    useState<string>('');

  const [exchanges, setExchanges] =
    useState<Exchange[]>([]);

  const [isLoading, setIsLoading] =
    useState<boolean>(false);

  const [validationMessage, setValidationMessage] =
    useState<string | null>(null);


  /* =======================================================
     REFS
     ======================================================= */

  const nextId =
    useRef<number>(0);

  const inputRef =
    useRef<HTMLTextAreaElement>(null);

  const transcriptEndRef =
    useRef<HTMLDivElement>(null);


  /* =======================================================
     AUTO SCROLL
     ======================================================= */

  useEffect(() => {

    transcriptEndRef.current?.scrollIntoView({
      behavior: 'smooth',
      block: 'nearest',
    });

  }, [exchanges]);


  /* =======================================================
     HELP RESPONSE
     ======================================================= */

  const HELP_RESPONSE = `Welcome to Ask GNOSIS.

GNOSIS is an organization security and access-management platform that helps employees securely access company resources while allowing administrators to manage permissions, monitor activity, detect suspicious access, and investigate security events.

You can ask GNOSIS about:

• Resources you can access
• Your access requests
• Your active access grants
• Your profile and role
• Information about resources available to you

Try asking:

“What resources can I access?”
“Show my access requests”
“What access grants do I have?”
“What is my role?”
“Tell me about the Employee Handbook”

GNOSIS only provides information that you are authorized to access.`;


  /* =======================================================
     NORMALIZE QUERY
     ======================================================= */

  function normalizeQuery(
    value: string,
  ): string {

    return value
      .toLowerCase()
      .replace(/[!?.,]/g, '')
      .trim();

  }


  /* =======================================================
     IS HELP QUERY?
     ======================================================= */

  function isHelpQuery(
    value: string,
  ): boolean {

    const normalized =
      normalizeQuery(value);

    const helpQueries = new Set([
      'help',
      'help me',
      'i need help',
      'can you help me',
      'what can you do',
      'what can i ask',
      'how can you help',
      'how do i use gnosis',
      'what is gnosis',
    ]);

    return helpQueries.has(normalized);

  }


  /* =======================================================
     SUBMIT QUESTION
     ======================================================= */

  async function submitQuestion(
    value?: string,
  ) {

    if (isLoading) {
      return;
    }


    const trimmed =
      (value ?? query).trim();


    /* -------------------------------------------------------
       EMPTY QUERY
       ------------------------------------------------------- */

    if (!trimmed) {

      setValidationMessage(
        'Enter a question to continue.',
      );

      inputRef.current?.focus();

      return;
    }


    /* -------------------------------------------------------
       CREATE EXCHANGE
       ------------------------------------------------------- */

    const id =
      nextId.current;

    nextId.current += 1;


    setValidationMessage(null);

    setQuery('');

    setIsLoading(true);


    setExchanges((previous) => [
      ...previous,

      {
        id,
        query: trimmed,
        answer: '',
        sources: [],
        status: 'pending',
        accessDenied: false,
      },
    ]);


    /* =====================================================
       HELP
       ===================================================== */

    if (isHelpQuery(trimmed)) {

      window.setTimeout(() => {

        setExchanges((previous) =>
          previous.map((exchange) =>
            exchange.id === id
              ? {
                ...exchange,

                answer:
                  HELP_RESPONSE,

                sources: [],

                status:
                  'success',

                accessDenied:
                  false,
              }
              : exchange,
          ),
        );

        setIsLoading(false);

      }, 350);

      return;
    }


    /* =====================================================
       NORMAL GNOSIS REQUEST
       ===================================================== */

    try {

      const result =
        await askGnosis(trimmed);


      setExchanges((previous) =>
        previous.map((exchange) =>
          exchange.id === id
            ? {
              ...exchange,

              answer:
                result.answer,

              sources:
                result.sources ?? [],

              accessDenied:
                result.access_denied,

              status:
                'success',
            }
            : exchange,
        ),
      );

    } catch (error) {

      const unauthorized =
        isUnauthorizedError(error);


      setExchanges((previous) =>
        previous.map((exchange) =>
          exchange.id === id
            ? {
              ...exchange,

              status:
                'error',

              answer:
                unauthorized
                  ? 'Your session has expired. Please sign in again.'
                  : 'GNOSIS could not process your request. Please try again.',
            }
            : exchange,
        ),
      );


      if (unauthorized) {
        logout();
      }

    } finally {

      setIsLoading(false);

    }

  }


  /* =======================================================
     FORM SUBMIT
     ======================================================= */

  function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {

    event.preventDefault();

    void submitQuestion();

  }


  /* =======================================================
     KEYBOARD
     ======================================================= */

  function handleKeyDown(
    event: KeyboardEvent<HTMLTextAreaElement>,
  ) {

    if (
      event.key === 'Enter' &&
      !event.shiftKey &&
      !event.nativeEvent.isComposing
    ) {

      event.preventDefault();

      void submitQuestion();

    }

  }


  /* =======================================================
     QUICK QUESTION
     ======================================================= */

  function handleQuickQuestion(
    question: string,
  ) {

    setValidationMessage(null);

    setQuery(question);

    requestAnimationFrame(() => {
      inputRef.current?.focus();
    });

  }


  /* =======================================================
     CLEAR CHAT
     ======================================================= */

  function clearChat() {

    if (isLoading) {
      return;
    }

    setExchanges([]);

    setQuery('');

    setValidationMessage(null);

  }


  /* =======================================================
     COPY RESPONSE
     ======================================================= */

  function copyResponse(
    answer: string,
  ) {

    if (!answer) {
      return;
    }

    void navigator.clipboard?.writeText(answer);

  }


  /* =======================================================
     ASK AGAIN
     ======================================================= */

  function askAgain(
    previousQuery: string,
  ) {

    if (isLoading) {
      return;
    }

    void submitQuestion(previousQuery);

  }


  /* =======================================================
     DERIVED STATE
     ======================================================= */

  const hasConversation =
    exchanges.length > 0;


  /* =========================================================
     RENDER
     ========================================================= */

  return (

    <section
      className="gnosis-chat"
      aria-label="Ask GNOSIS"
    >


      {/* ===================================================
          BRAND
          =================================================== */}

      <div className="gnosis-chat__brand">

        <div className="gnosis-chat__brand-mark">
          <Sparkles size={20} />
        </div>

        <div>

          <div className="gnosis-chat__brand-name">
            GNOSIS
          </div>

          <div className="gnosis-chat__brand-status">
            Authorized information assistant
          </div>

        </div>

      </div>


      {/* ===================================================
          HEADER
          =================================================== */}

      <header className="gnosis-chat__header">

        <div>

          <h1>
            Ask GNOSIS
          </h1>

          <p>
            Ask questions about your authorized company
            resources, permissions, requests, and profile.
          </p>

        </div>


        <button
          type="button"
          className="gnosis-chat__new-chat"
          onClick={clearChat}
          disabled={
            isLoading ||
            !hasConversation
          }
        >

          <Plus size={16} />

          New chat

        </button>

      </header>


      {/* ===================================================
          WORKSPACE
          =================================================== */}

      <div className="gnosis-chat__workspace">


        {/* =================================================
            MAIN CONVERSATION
            ================================================= */}

        <main className="gnosis-chat__conversation">


          {!hasConversation ? (

            /* =================================================
               WELCOME SCREEN
               ================================================= */

            <div className="gnosis-chat__welcome">


              <div className="gnosis-chat__welcome-icon">
                <Sparkles size={28} />
              </div>


              <h2>
                How can I help you?
              </h2>


              <p>
                Ask GNOSIS about information you are
                authorized to access.
              </p>


              {/* =============================================
                  QUICK ACTIONS
                  ============================================= */}

              <div className="gnosis-chat__welcome-grid">


                <button
                  type="button"
                  onClick={() =>
                    handleQuickQuestion(
                      'What resources can I access?',
                    )
                  }
                >

                  <BookOpen size={18} />

                  <span>

                    <strong>
                      My Resources
                    </strong>

                    <small>
                      View resources available to you
                    </small>

                  </span>

                </button>


                <button
                  type="button"
                  onClick={() =>
                    handleQuickQuestion(
                      'Show me my access requests',
                    )
                  }
                >

                  <Clock3 size={18} />

                  <span>

                    <strong>
                      Access Requests
                    </strong>

                    <small>
                      Check your pending requests
                    </small>

                  </span>

                </button>


                <button
                  type="button"
                  onClick={() =>
                    handleQuickQuestion(
                      'What access grants do I have?',
                    )
                  }
                >

                  <ShieldCheck size={18} />

                  <span>

                    <strong>
                      Access Grants
                    </strong>

                    <small>
                      See your current permissions
                    </small>

                  </span>

                </button>


                <button
                  type="button"
                  onClick={() =>
                    handleQuickQuestion(
                      'What is my role?',
                    )
                  }
                >

                  <User size={18} />

                  <span>

                    <strong>
                      My Profile
                    </strong>

                    <small>
                      View your GNOSIS profile
                    </small>

                  </span>

                </button>


              </div>


              {/* =============================================
                  QUICK QUESTIONS
                  ============================================= */}

              {/* <div className="gnosis-chat__quick-questions">

                <span>
                  TRY ASKING
                </span>


                <div>

                  {QUICK_QUESTIONS.map(
                    (question) => (

                      <button
                        key={question}
                        type="button"
                        onClick={() =>
                          handleQuickQuestion(
                            question,
                          )
                        }
                      >
                        {question}
                      </button>

                    ),
                  )}

                </div>

              </div> */}


            </div>


          ) : (


            /* =================================================
               CONVERSATION
               ================================================= */

            <div className="gnosis-chat__messages">


              {exchanges.map(
                (exchange) => (

                  <article
                    key={exchange.id}
                    className="gnosis-chat__exchange"
                  >


                    {/* =========================================
                        USER MESSAGE
                        ========================================= */}

                    <div className="gnosis-chat__user-message">


                      <div className="gnosis-chat__user-avatar">

                        {user?.name
                          ?.charAt(0)
                          .toUpperCase() || 'U'}

                      </div>


                      <div className="gnosis-chat__user-bubble">

                        <span className="gnosis-chat__message-label">
                          YOU
                        </span>

                        <p>
                          {exchange.query}
                        </p>

                      </div>

                    </div>


                    {/* =========================================
                        GNOSIS MESSAGE
                        ========================================= */}

                    <div className="gnosis-chat__assistant-message">


                      <div className="gnosis-chat__assistant-avatar">

                        <Sparkles size={19} />

                      </div>


                      <div className="gnosis-chat__assistant-content">


                        <span className="gnosis-chat__message-label">
                          GNOSIS
                        </span>


                        {exchange.status === 'pending' ? (


                          /* ===================================
                             THINKING
                             =================================== */

                          <div className="gnosis-chat__thinking">

                            <span />
                            <span />
                            <span />

                            <p>
                              GNOSIS is thinking...
                            </p>

                          </div>


                        ) : (


                          <>


                            {/* =================================
                                RESPONSE
                                ================================= */}

                            <p
                              className={
                                exchange.status ===
                                  'error'
                                  ? 'gnosis-chat__error'
                                  : ''
                              }
                            >
                              {exchange.answer}
                            </p>


                            {/* =================================
                                ACTIONS
                                ================================= */}

                            {exchange.status ===
                              'success' && (

                                <div className="gnosis-chat__response-actions">


                                  <button
                                    type="button"
                                    onClick={() =>
                                      copyResponse(
                                        exchange.answer,
                                      )
                                    }
                                  >

                                    <Copy size={13} />

                                    <span>
                                      Copy
                                    </span>

                                  </button>


                                  <button
                                    type="button"
                                    onClick={() =>
                                      askAgain(
                                        exchange.query,
                                      )
                                    }
                                    disabled={isLoading}
                                  >

                                    <RotateCcw size={13} />

                                    <span>
                                      Ask again
                                    </span>

                                  </button>


                                </div>

                              )}


                            {/* =================================
                                SOURCES
                                ================================= */}

                            {exchange.sources.length >
                              0 && (

                                <div className="gnosis-chat__sources">


                                  <div className="gnosis-chat__sources-title">
                                    Sources
                                  </div>


                                  {exchange.sources.map(
                                    (
                                      source,
                                      index,
                                    ) => (

                                      <div
                                        key={`${source}-${index}`}
                                        className="gnosis-chat__source"
                                      >

                                        <FileText
                                          size={14}
                                        />

                                        <span>
                                          {source}
                                        </span>

                                      </div>

                                    ),
                                  )}

                                </div>

                              )}

                          </>

                        )}

                      </div>

                    </div>


                  </article>

                ),
              )}


              <div
                ref={transcriptEndRef}
              />


            </div>

          )}

        </main>


        {/* =================================================
            HISTORY
            ================================================= */}

        <aside className="gnosis-chat__history">


          <div className="gnosis-chat__history-header">

            <div>

              <span>
                HISTORY
              </span>

              <h3>
                Recent chats
              </h3>

            </div>

            <MessageSquare size={18} />

          </div>


          {exchanges.length === 0 ? (

            <div className="gnosis-chat__history-empty">

              Your conversations will appear here.

            </div>

          ) : (

            <div className="gnosis-chat__history-list">

              {exchanges
                .slice()
                .reverse()
                .map(
                  (exchange) => (

                    <button
                      key={exchange.id}
                      type="button"
                      onClick={() =>
                        transcriptEndRef.current?.scrollIntoView({
                          behavior: 'smooth',
                          block: 'nearest',
                        })
                      }
                    >

                      <MessageSquare
                        size={14}
                      />

                      <span>
                        {exchange.query}
                      </span>

                    </button>

                  ),
                )}

            </div>

          )}

        </aside>


      </div>


      {/* ===================================================
          COMPOSER
          =================================================== */}

      <form
        className="gnosis-chat__composer"
        onSubmit={handleSubmit}
        noValidate
      >


        <textarea
          ref={inputRef}
          value={query}
          maxLength={MAX_QUERY_LENGTH}
          rows={1}
          placeholder="Ask GNOSIS anything..."
          onChange={(event) => {

            setQuery(
              event.target.value,
            );

            if (validationMessage) {

              setValidationMessage(
                null,
              );

            }

          }}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          aria-label="Ask GNOSIS"
        />


        <div className="gnosis-chat__composer-bottom">


          <div className="gnosis-chat__composer-info">

            <ShieldCheck size={15} />

            <span>
              Authorized information only
            </span>

            <span className="gnosis-chat__counter">
              {query.length}/{MAX_QUERY_LENGTH}
            </span>

          </div>


          <button
            type="submit"
            className="gnosis-chat__send"
            disabled={
              isLoading ||
              !query.trim()
            }
            aria-label="Send message"
          >

            <ArrowUp size={21} />

          </button>


        </div>


        {validationMessage && (

          <div className="gnosis-chat__validation">

            {validationMessage}

          </div>

        )}


      </form>


      {/* ===================================================
          FOOTER
          =================================================== */}

      <p className="gnosis-chat__footer">

        GNOSIS only responds using information you are
        authorized to access.

      </p>


    </section>

  );

}