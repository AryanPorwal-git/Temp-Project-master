import { useState, useEffect } from 'react';
import ReCAPTCHA from 'react-google-recaptcha';
import { Eye, EyeOff, Lock, Mail, ArrowRight } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import './App.css';
import { Amplify } from 'aws-amplify';
import { signIn, signUp, confirmSignUp, confirmSignIn, signOut } from 'aws-amplify/auth';

Amplify.configure({
  Auth: {
    Cognito: {
      userPoolId: 'us-east-1_qpmIwLCMG',
      userPoolClientId: '2g2ltrfc4ema927br7unc7qsps',
      signUpVerificationMethod: 'link'
    }
  }
});

export default function App() {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [recaptchaToken, setRecaptchaToken] = useState('');
  const [userSession, setUserSession] = useState(null);
  const [step, setStep] = useState('auth');
  
  // ToS state
  const [acceptedTos, setAcceptedTos] = useState(false);
  const [tosContent, setTosContent] = useState('');
  const [showTosModal, setShowTosModal] = useState(false);
  const [latestTosVersion, setLatestTosVersion] = useState('1.0');

  // Load ToS content and version
  useEffect(() => {
    const loadTosContent = async () => {
      try {
        const response = await fetch('https://raw.githubusercontent.com/AryanPorwal-git/my-tos/main/v1.md');
        const text = await response.text();
        setTosContent(text);
      } catch (error) {
        setTosContent('# Terms of Service\n\nUnable to load Terms. Please try again later.');
        setError('Failed to load Terms of Service');
      }
    };
    
    const loadTosVersion = async () => {
      setLatestTosVersion('1.0');
    };

    loadTosContent();
    loadTosVersion();
  }, []);

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [confirmationCode, setConfirmationCode] = useState('');

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    setError('');
  };

  const handleSignIn = async (e) => {
    if (e) e.preventDefault();

    if (!acceptedTos) {
      setError('You must accept the Terms of Service');
      return;
    }

    if (!recaptchaToken) {
      setError('Please complete the reCAPTCHA verification');
      return;
    }

    const { email, password } = formData;

    if (!email || !password) {
      setError('Email and password are required');
      return;
    }

    setIsLoading(true);

    try {
      const { isSignedIn, nextStep, userId } = await signIn({
        username: email,
        password,
        options: {
          authFlowType: 'CUSTOM_WITH_SRP'
        }
      });
      setUserSession({ userId });

      if (nextStep.signInStep === 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE') {
        const challengeResponse = recaptchaToken;
        const { isSignedIn: signedIn, nextStep: next } = await confirmSignIn({
          challengeResponse,
          userId
        });
        if (signedIn && next.signInStep === 'DONE') {
          setSuccess('Sign in successful!');
          setError('');
        } else {
          setError('reCAPTCHA failed');
          setSuccess('');
        }
      } else if (isSignedIn || nextStep.signInStep === 'DONE') {
        setSuccess('Sign in successful!');
        setError('');
      } else if (nextStep.signInStep === 'CONFIRM_SIGN_UP') {
        setStep('confirmSignUp');
        setSuccess('Please confirm your sign up with the code sent to your email.');
        setError('');
      } else {
        setError('Unexpected next step: ' + nextStep.signInStep);
        setSuccess('');
      }
    } catch (err) {
      if (err.message?.includes('TOS_VERSION_MISMATCH')) {
        const parts = err.message.split(':');
        const requiredVersion = parts[1] || latestTosVersion;
        setLatestTosVersion(requiredVersion);
        setShowTosModal(true);
        setError('Please accept the latest Terms of Service');
        setAcceptedTos(false);
      } else if (err.message?.includes('already a signed in user')) {
        setError('A user is already signed in. Please sign out first.');
      } else {
        setError(err.message || 'Sign in failed. Please try again.');
      }
      setSuccess('');
    } finally {
      setIsLoading(false);
      setRecaptchaToken('');
    }
  };

  const handleSignUp = async (e) => {
    if (e) e.preventDefault();

    if (!acceptedTos) {
      setError('You must accept the Terms of Service');
      return;
    }

    if (!recaptchaToken) {
      setError('Please complete the reCAPTCHA verification');
      return;
    }

    const { email, password, confirmPassword } = formData;

    if (!email || !password) {
      setError('All fields are required');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setIsLoading(true);

    try {
      await signUp({
        username: email,
        password,
        options: {
          userAttributes: {
            email,
            'custom:tos_version': latestTosVersion
          },
          validationData: { token: recaptchaToken }
        }
      });
      setStep('confirmSignUp');
      setSuccess('Sign up successful! Please enter the code sent to your email.');
      setError('');
    } catch (err) {
      if (err.message?.includes('TOS_VERSION_MISMATCH')) {
        const parts = err.message.split(':');
        const requiredVersion = parts[1] || latestTosVersion;
        setLatestTosVersion(requiredVersion);
        setShowTosModal(true);
        setError('Please accept the latest Terms of Service');
        setAcceptedTos(false);
      } else {
        setError(err.message || 'Sign up failed. Please try again.');
      }
      setSuccess('');
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmSignUp = async (e) => {
    if (e) e.preventDefault();

    if (!confirmationCode) {
      setError('Please enter the confirmation code sent to your email.');
      return;
    }

    setIsLoading(true);

    try {
      await confirmSignUp({
        username: formData.email,
        confirmationCode
      });
      setSuccess('Email confirmed! You can now sign in.');
      setError('');
      setStep('auth');
      setIsLogin(true);
    } catch (err) {
      setError(err.message || 'Confirmation failed. Please try again.');
      setSuccess('');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut();
      setSuccess('Signed out!');
      setShowPassword(false);
      setUserSession(null);
      setFormData({
        email: '',
        password: '',
        confirmPassword: ''
      });
      setConfirmationCode('');
      setStep('auth');
      setIsLogin(true);
      setError('');
      setAcceptedTos(false);
    } catch (e) {
      setError('Sign out failed: ' + (e.message || e));
    }
  };

  const toggleAuthMode = () => {
    setIsLogin(!isLogin);
    setError('');
    setSuccess('');
    setStep('auth');
    setFormData({
      email: '',
      password: '',
      confirmPassword: ''
    });
    setConfirmationCode('');
    setAcceptedTos(false);
  };

  const TosModal = () => (
    <div className="tos-modal" onClick={() => setShowTosModal(false)}>
      <div className="tos-content" onClick={(e) => e.stopPropagation()}>
        <button
          className="close-button"
          onClick={() => setShowTosModal(false)}
        >
          ×
        </button>
        <ReactMarkdown>{tosContent}</ReactMarkdown>
        <div className="tos-version">Version {latestTosVersion}</div>
      </div>
    </div>
  );

  return (
    <div className="auth-container">
      {showTosModal && <TosModal />}
      <div className="auth-card">
        <div className="auth-header">
          <h2>
            {step === 'auth'
              ? isLogin
                ? 'Sign in to your account'
                : 'Create a new account'
              : 'Confirm your email'}
          </h2>
          {step === 'auth' && (
            <p>
              {isLogin ? "Don't have an account? " : "Already have an account? "}
              <button onClick={toggleAuthMode} className="text-link">
                {isLogin ? 'Sign up' : 'Sign in'}
              </button>
            </p>
          )}
        </div>

        {error && <div className="auth-message error">{error}</div>}
        {success && <div className="auth-message success">{success}</div>}

        {step === 'auth' && (
          <form className="auth-form" onSubmit={isLogin ? handleSignIn : handleSignUp}>
            <div className="form-fields">
              <div className="input-group">
                <label htmlFor="email" className="sr-only">
                  Email
                </label>
                <div className="input-icon">
                  <Mail />
                </div>
                <input
                  id="email"
                  name="email"
                  type="email"
                  required
                  value={formData.email}
                  onChange={handleInputChange}
                  placeholder="Email"
                />
              </div>

              <div className="input-group">
                <label htmlFor="password" className="sr-only">
                  Password
                </label>
                <div className="input-icon">
                  <Lock />
                </div>
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={formData.password}
                  onChange={handleInputChange}
                  placeholder="Password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="password-toggle"
                >
                  {showPassword ? <EyeOff /> : <Eye />}
                </button>
              </div>

              {!isLogin && (
                <div className="input-group">
                  <label htmlFor="confirmPassword" className="sr-only">
                    Confirm Password
                  </label>
                  <div className="input-icon">
                    <Lock />
                  </div>
                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={formData.confirmPassword}
                    onChange={handleInputChange}
                    placeholder="Confirm Password"
                  />
                </div>
              )}

              <div className="tos-checkbox">
                <input
                  type="checkbox"
                  id="tos"
                  checked={acceptedTos}
                  onChange={(e) => setAcceptedTos(e.target.checked)}
                  required
                />
                <label htmlFor="tos">
                  I agree to the{' '}
                  <button
                    type="button"
                    className="text-link"
                    onClick={() => setShowTosModal(true)}
                  >
                    Terms of Service (v{latestTosVersion})
                  </button>
                </label>
              </div>

              <div className={`recaptcha-container ${!acceptedTos ? 'recaptcha-disabled' : ''}`}>
                <ReCAPTCHA
                  sitekey="6LdZFDsrAAAAAMXFRxbxqmaEOhDxZ2V1MSlQ-r3P"
                  onChange={(token) => setRecaptchaToken(token)}
                  theme="light"
                  size="normal"
                />
              </div>
            </div>

            <div className="form-actions">
              <button
                type="submit"
                disabled={isLoading}
                className="submit-button"
              >
                {isLoading ? (
                  <span>Processing...</span>
                ) : (
                  <>
                    <span>{isLogin ? 'Sign in' : 'Sign up'}</span>
                    <ArrowRight className="button-icon" />
                  </>
                )}
              </button>
            </div>
          </form>
        )}

        {step === 'confirmSignUp' && (
          <form className="auth-form" onSubmit={handleConfirmSignUp}>
            <div className="form-fields">
              <div className="input-group">
                <label htmlFor="confirmationCode" className="sr-only">
                  Confirmation Code
                </label>
                <input
                  id="confirmationCode"
                  name="confirmationCode"
                  type="text"
                  required
                  value={confirmationCode}
                  onChange={(e) => setConfirmationCode(e.target.value)}
                  placeholder="Enter the code sent to your email"
                />
              </div>
            </div>
            <div className="form-actions">
              <button
                type="submit"
                disabled={isLoading}
                className="submit-button"
              >
                {isLoading ? <span>Verifying...</span> : <span>Confirm</span>}
              </button>
            </div>
          </form>
        )}

        <div style={{ marginTop: 16 }}>
          <button onClick={handleSignOut} className="text-link">
            Sign Out
          </button>
        </div>

        {isLogin && step === 'auth' && (
          <div className="forgot-password">
            <button type="button" className="text-link">
              Forgot your password?
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
