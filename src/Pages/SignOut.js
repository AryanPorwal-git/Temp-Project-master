import { useState } from 'react';
import { signOut } from 'aws-amplify/auth';
import { ArrowRight, LogOut } from 'lucide-react';

export default function SignOut() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSignOut = async () => {
    setIsLoading(true);
    try {
      await signOut({ global: true });
      setSuccess('Successfully signed out');
      // Redirect to sign-in page after a short delay
      setTimeout(() => {
        window.location.href = '/';
      }, 2000);
    } catch (err) {
      console.error(err);
      setError(err.message || 'Sign out failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Account Dashboard</h2>
          <p>You are currently signed in</p>
        </div>

        {error && (
          <div className="auth-message error">
            {error}
          </div>
        )}
        
        {success && (
          <div className="auth-message success">
            {success}
          </div>
        )}

        <div className="auth-form">
          <div className="form-actions">
            <button
              type="button"
              onClick={handleSignOut}
              className="submit-button"
              disabled={isLoading}
            >
              {isLoading ? (
                <span>Processing...</span>
              ) : (
                <>
                  <span>Sign Out</span>
                  <LogOut className="button-icon" />
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
