import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  Database,
  HelpCircle,
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  Users,
  XCircle,
} from 'lucide-react';

import './AdminDashboard.css';

type PerformanceStatus = 'up' | 'stable' | 'down';

interface Employee {
  name: string;
  department: string;
  activity: number;
  questions: number;
  relevantQuestions: number;
  status: PerformanceStatus;
}

const employees: Employee[] = [
  {
    name: 'Prapti Singhal',
    department: 'HR',
    activity: 92,
    questions: 29,
    relevantQuestions: 28,
    status: 'up',
  },
  {
    name: 'Om Shukla',
    department: 'IT',
    activity: 86,
    questions: 24,
    relevantQuestions: 23,
    status: 'up',
  },
  {
    name: 'Aarav Mehta',
    department: 'Finance',
    activity: 68,
    questions: 21,
    relevantQuestions: 17,
    status: 'stable',
  },
  {
    name: 'Riya Kapoor',
    department: 'Sales',
    activity: 51,
    questions: 42,
    relevantQuestions: 31,
    status: 'down',
  },
  {
    name: 'Kunal Verma',
    department: 'HR',
    activity: 39,
    questions: 36,
    relevantQuestions: 27,
    status: 'down',
  },
];

const departments = [
  { name: 'IT', value: 94, employees: 2 },
  { name: 'HR', value: 76, employees: 2 },
  { name: 'Finance', value: 58, employees: 1 },
  { name: 'Sales', value: 46, employees: 1 },
];

const securityEvents = [
  {
    time: '20:31',
    employee: 'Riya Kapoor',
    event: 'Repeated access denial',
    severity: 'High',
  },
  {
    time: '19:48',
    employee: 'Om Shukla',
    event: 'Resource access',
    severity: 'Low',
  },
  {
    time: '18:22',
    employee: 'Kunal Verma',
    event: 'Failed authentication',
    severity: 'Medium',
  },
  {
    time: '17:51',
    employee: 'Aarav Mehta',
    event: 'Access request submitted',
    severity: 'Low',
  },
];

function PerformanceIndicator({
  status,
}: {
  status: PerformanceStatus;
}) {
  if (status === 'up') {
    return (
      <span className="performance-indicator performance-up">
        <ArrowUpRight size={14} />
      </span>
    );
  }

  if (status === 'down') {
    return (
      <span className="performance-indicator performance-down">
        <ArrowDownRight size={14} />
      </span>
    );
  }

  return (
    <span className="performance-indicator performance-stable">
      →
    </span>
  );
}

function Avatar({ name }: { name: string }) {
  const initials = name
    .split(' ')
    .map((part) => part[0])
    .join('')
    .slice(0, 2);

  return (
    <div className="admin-avatar">
      {initials}
    </div>
  );
}

export function AdminDashboard() {
  const totalEmployees = employees.length;

  const totalQuestions = employees.reduce(
    (sum, employee) => sum + employee.questions,
    0
  );

  const relevantQuestions = employees.reduce(
    (sum, employee) => sum + employee.relevantQuestions,
    0
  );

  const lowRelevanceQuestions =
    totalQuestions - relevantQuestions;

  const relevancePercentage = Math.round(
    (relevantQuestions / totalQuestions) * 100
  );

  return (
    <div className="admin-dashboard">

      {/* PAGE HEADER */}
      <section className="admin-page-header">
        <div>
          <div className="admin-eyebrow">
            <ShieldCheck size={15} />
            SECURITY CONSOLE
          </div>

          <h1>Organization Overview</h1>

          <p>
            Monitor employee activity, GNOSIS usage, access
            behaviour and security events from one place.
          </p>
        </div>

        <div className="admin-header-status">
          <span className="status-dot" />
          System protected
        </div>
      </section>

      {/* OVERVIEW CARDS */}
      <section className="admin-stat-grid">

        <div className="admin-stat-card">
          <div className="stat-icon blue">
            <Users size={20} />
          </div>

          <div className="stat-content">
            <span>Total Employees</span>
            <strong>{totalEmployees}</strong>
            <small>Active organization members</small>
          </div>

          <div className="stat-arrow">
            <ArrowUpRight size={18} />
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="stat-icon green">
            <Activity size={20} />
          </div>

          <div className="stat-content">
            <span>Active Sessions</span>
            <strong>4</strong>
            <small>Currently active</small>
          </div>

          <div className="stat-arrow">
            <ArrowUpRight size={18} />
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="stat-icon amber">
            <Clock3 size={20} />
          </div>

          <div className="stat-content">
            <span>Access Requests</span>
            <strong>3</strong>
            <small>2 require review</small>
          </div>

          <div className="stat-arrow">
            <ArrowUpRight size={18} />
          </div>
        </div>

        <div className="admin-stat-card">
          <div className="stat-icon red">
            <ShieldAlert size={20} />
          </div>

          <div className="stat-content">
            <span>Security Events</span>
            <strong>7</strong>
            <small>1 high severity</small>
          </div>

          <div className="stat-arrow">
            <ArrowUpRight size={18} />
          </div>
        </div>

      </section>

      {/* ACTIVITY + ASK GNOSIS */}
      <section className="admin-main-grid">

        {/* ACTIVITY CHART */}
        <div className="admin-card activity-card">

          <div className="card-header">
            <div>
              <span className="card-kicker">ORGANIZATION</span>
              <h2>GNOSIS Activity</h2>
            </div>

            <select className="period-select" defaultValue="30">
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 3 months</option>
            </select>
          </div>

          <div className="activity-summary">
            <div>
              <strong>184</strong>
              <span>total activities</span>
            </div>

            <div className="activity-change">
              <ArrowUpRight size={15} />
              12.4%
            </div>
          </div>

          <div className="chart-container">
            <div className="chart-y-axis">
              <span>40</span>
              <span>30</span>
              <span>20</span>
              <span>10</span>
              <span>0</span>
            </div>

            <div className="chart-area">

              <div className="chart-grid-line line-1" />
              <div className="chart-grid-line line-2" />
              <div className="chart-grid-line line-3" />
              <div className="chart-grid-line line-4" />
              <div className="chart-grid-line line-5" />

              <svg
                className="activity-chart"
                viewBox="0 0 700 240"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient
                    id="activityFill"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor="#1769e0"
                      stopOpacity="0.20"
                    />
                    <stop
                      offset="100%"
                      stopColor="#1769e0"
                      stopOpacity="0"
                    />
                  </linearGradient>
                </defs>

                <path
                  d="
                    M 0 190
                    C 50 180, 70 130, 120 145
                    C 170 160, 180 185, 230 145
                    C 280 105, 300 115, 340 65
                    C 380 15, 420 35, 455 80
                    C 500 135, 520 175, 565 140
                    C 610 105, 630 120, 700 70
                    L 700 240
                    L 0 240
                    Z
                  "
                  fill="url(#activityFill)"
                />

                <path
                  d="
                    M 0 190
                    C 50 180, 70 130, 120 145
                    C 170 160, 180 185, 230 145
                    C 280 105, 300 115, 340 65
                    C 380 15, 420 35, 455 80
                    C 500 135, 520 175, 565 140
                    C 610 105, 630 120, 700 70
                  "
                  fill="none"
                  stroke="#1769e0"
                  strokeWidth="4"
                  strokeLinecap="round"
                />

                <circle
                  cx="340"
                  cy="65"
                  r="6"
                  fill="#ffffff"
                  stroke="#1769e0"
                  strokeWidth="4"
                />
              </svg>

              <div className="chart-tooltip">
                <strong>26 Jun</strong>
                <span>34 activities</span>
              </div>
            </div>
          </div>

          <div className="chart-labels">
            <span>Mon</span>
            <span>Tue</span>
            <span>Wed</span>
            <span>Thu</span>
            <span>Fri</span>
            <span>Sat</span>
            <span>Sun</span>
          </div>

        </div>

        {/* ASK GNOSIS */}
        <div className="admin-card ask-card">

          <div className="card-header">
            <div>
              <span className="card-kicker">ASSISTANT ANALYTICS</span>
              <h2>Ask GNOSIS</h2>
            </div>

            <div className="ask-icon">
              <MessageSquare size={20} />
            </div>
          </div>

          <div className="question-total">
            <strong>{totalQuestions}</strong>
            <span>questions this period</span>
          </div>

          <div className="question-progress">

            <div className="progress-label">
              <span>
                Relevant questions
              </span>

              <strong>{relevancePercentage}%</strong>
            </div>

            <div className="progress-track">
              <div
                className="progress-fill"
                style={{
                  width: `${relevancePercentage}%`,
                }}
              />
            </div>

          </div>

          <div className="question-breakdown">

            <div className="question-row">
              <div className="question-row-icon relevant">
                <CheckCircle2 size={15} />
              </div>

              <div>
                <strong>{relevantQuestions}</strong>
                <span>Relevant</span>
              </div>
            </div>

            <div className="question-row">
              <div className="question-row-icon warning">
                <HelpCircle size={15} />
              </div>

              <div>
                <strong>{lowRelevanceQuestions}</strong>
                <span>Low relevance</span>
              </div>
            </div>

          </div>

          <div className="ask-note">
            <MessageSquare size={15} />

            <span>
              Low-relevance activity is flagged for
              administrator review rather than treated as
              a policy violation.
            </span>
          </div>

        </div>

      </section>

      {/* PERFORMANCE + ATTENTION */}
      <section className="admin-main-grid">

        {/* PERFORMANCE */}
        <div className="admin-card">

          <div className="card-header">
            <div>
              <span className="card-kicker">EMPLOYEE ANALYTICS</span>
              <h2>Employee Performance</h2>
            </div>

            <button className="text-button">
              View all
            </button>
          </div>

          <div className="employee-list">

            {employees.slice(0, 4).map((employee) => (
              <div
                className="employee-performance-row"
                key={employee.name}
              >
                <div className="employee-person">
                  <Avatar name={employee.name} />

                  <div>
                    <strong>{employee.name}</strong>
                    <span>{employee.department}</span>
                  </div>
                </div>

                <div className="employee-score">
                  <div className="score-bar">
                    <div
                      className="score-fill"
                      style={{
                        width: `${employee.activity}%`,
                      }}
                    />
                  </div>

                  <strong>
                    {employee.activity}%
                  </strong>

                  <PerformanceIndicator
                    status={employee.status}
                  />
                </div>
              </div>
            ))}

          </div>

        </div>

        {/* REQUIRES ATTENTION */}
        <div className="admin-card">

          <div className="card-header">
            <div>
              <span className="card-kicker">REVIEW QUEUE</span>
              <h2>Requires Attention</h2>
            </div>

            <div className="attention-count">
              3
            </div>
          </div>

          <div className="attention-list">

            <div className="attention-item">
              <Avatar name="Riya Kapoor" />

              <div className="attention-info">
                <strong>Riya Kapoor</strong>
                <span>
                  Repeated access denials
                </span>
              </div>

              <span className="severity-badge high">
                High
              </span>
            </div>

            <div className="attention-item">
              <Avatar name="Kunal Verma" />

              <div className="attention-info">
                <strong>Kunal Verma</strong>
                <span>
                  Low activity pattern
                </span>
              </div>

              <span className="severity-badge medium">
                Review
              </span>
            </div>

            <div className="attention-item">
              <Avatar name="Aarav Mehta" />

              <div className="attention-info">
                <strong>Aarav Mehta</strong>
                <span>
                  Pending access request
                </span>
              </div>

              <span className="severity-badge low">
                Pending
              </span>
            </div>

          </div>

        </div>

      </section>

      {/* DEPARTMENT ACTIVITY */}
      <section className="admin-card department-card">

        <div className="card-header">
          <div>
            <span className="card-kicker">
              ORGANIZATION BREAKDOWN
            </span>

            <h2>Department Activity</h2>
          </div>

          <span className="card-caption">
            Activity index
          </span>
        </div>

        <div className="department-grid">

          {departments.map((department) => (
            <div
              className="department-item"
              key={department.name}
            >
              <div className="department-top">
                <div>
                  <strong>{department.name}</strong>
                  <span>
                    {department.employees}{' '}
                    {department.employees === 1
                      ? 'employee'
                      : 'employees'}
                  </span>
                </div>

                <strong>{department.value}%</strong>
              </div>

              <div className="department-track">
                <div
                  className="department-fill"
                  style={{
                    width: `${department.value}%`,
                  }}
                />
              </div>
            </div>
          ))}

        </div>

      </section>

      {/* SECURITY EVENTS */}
      <section className="admin-card security-events-card">

        <div className="card-header">
          <div>
            <span className="card-kicker">
              SECURITY MONITORING
            </span>

            <h2>Recent Security Events</h2>
          </div>

          <button className="text-button">
            View audit logs
          </button>
        </div>

        <div className="security-table">

          <div className="security-table-header">
            <span>TIME</span>
            <span>EMPLOYEE</span>
            <span>EVENT</span>
            <span>SEVERITY</span>
          </div>

          {securityEvents.map((event) => (
            <div
              className="security-table-row"
              key={`${event.time}-${event.employee}`}
            >
              <span className="event-time">
                {event.time}
              </span>

              <div className="event-user">
                <Avatar name={event.employee} />
                <strong>{event.employee}</strong>
              </div>

              <span className="event-description">
                {event.event}
              </span>

              <span
                className={`severity-badge ${event.severity.toLowerCase()}`}
              >
                {event.severity}
              </span>
            </div>
          ))}

        </div>

      </section>

      {/* FOOTER */}
      <div className="admin-security-footer">
        <ShieldCheck size={16} />

        <span>
          GNOSIS security monitoring is active
        </span>

        <span className="footer-separator">•</span>

        <span>
          Access decisions are enforced by policy
        </span>
      </div>

    </div>
  );
}