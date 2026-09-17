// Drishti v0.1 — React error boundary | 11-Jul-2026
import { Component, type ReactNode } from "react";
import { ErrorState } from "./primitives";

interface Props {
  children: ReactNode;
  label?: string;
}
interface State {
  hasError: boolean;
}

/** Route-level boundary: catches render crashes (React Flow can throw on bad
 * data), shows an in-voice fallback, isolates the failure (ERROR_HANDLING.md §3.1). */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };
  static getDerivedStateFromError(): State {
    return { hasError: true };
  }
  componentDidCatch(error: unknown) {
    console.error("[drishti] view crashed:", error);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8">
          <ErrorState
            message={`Something went wrong rendering ${this.props.label ?? "this view"}.`}
            onRetry={() => this.setState({ hasError: false })}
          />
        </div>
      );
    }
    return this.props.children;
  }
}
