import { useState, useEffect } from 'react';
import ReCAPTCHA from 'react-google-recaptcha';
import { Eye, EyeOff, Lock, Mail, ArrowRight } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { createHash } from 'crypto-browserify';
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
  const [tosChallenge, setTosChallenge] = useState(null);
  
  // ToS state
  const [acceptedTos, setAcceptedTos] = useState(false);
  const [tosContent, setTosContent] = useState('');
  const [showTosModal, setShowTosModal] = useState(false);
  const [tosSha, setTosSha] = useState('');

  // Load ToS content directly from S3
  useEffect(() => {
    const loadTos = async () => {
      try {
        const response = await fetch('https://your-tos-bucket.s3.amazonaws.com/tos.md');
        const content = await response.text();
        setTosContent(content);
        
        // Compute SHA-256 hash
        const hash = createHash('sha256').update(content).digest('hex');
        setTosSha(hash);
      } catch (error) {
        setTosContent('# Terms of Service\n\nUnable to load Terms. Please try again later.');
        setError('Failed to load Terms of Service');
      }
    };
    
    loadTos();
  }, []);

  // Form fields
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [confirmationCode, setConfirmationCode] = useState('');

  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    setError('');
  };

  // Handle Sign In
  const handleSignIn = async (e) => {
    if (e) e.preventDefault();

    if (!recaptchaToken && step !== 'tos') {
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
        const challengeName = nextStep.challengeName;
        
        if (challengeName === 'CUSTOM_TOS_CHALLENGE') {
          setTosChallenge(nextStep);
          setStep('tos');
          setError('');
          setSuccess('Please review and accept the updated Terms of Service');
        } else {
          const { isSignedIn: signedIn } = await confirmSignIn({
            challengeResponse: recaptchaToken
          });
          
          if (signedIn) {
            setSuccess('Sign in successful!');
            setError('');
          } else {
            setError('reCAPTCHA verification failed');
          }
        }
      } else if (isSignedIn) {
        setSuccess('Sign in successful!');
        setError('');
      } else if (nextStep.signInStep === 'CONFIRM_SIGN_UP') {
        setStep('confirmSignUp');
        setSuccess('Please confirm your sign up with the code sent to your email.');
        setError('');
      } else {
        setError('Unexpected authentication step');
      }
    } catch (err) {
      if (err.message?.includes('already a signed in user')) {
        setError('A user is already signed in. Please sign out first.');
      } else if (err.message?.includes('TOS_SHA_MISMATCH')) {
        setStep('tos');
        setError('Please accept the updated Terms of Service');
      } else {
        setError(err.message || 'Sign in failed. Please try again.');
      }
      setSuccess('');
    } finally {
      setIsLoading(false);
      setRecaptchaToken('');
    }
  };
    // Handle ToS Acceptance
  const handleTosAccept = async () => {
    if (!acceptedTos) {
      setError('You must accept the Terms of Service');
      return;
    }

    setIsLoading(true);
    
    try {
      const { isSignedIn, nextStep } = await confirmSignIn({
        challengeResponse: tosSha,
        options: {
          authFlowType: 'CUSTOM_WITHOUT_SRP'
        }
      });

      if (nextStep?.challengeName === 'CUSTOM_CHALLENGE') {
        setStep('auth');
        setSuccess('Terms accepted. Please complete CAPTCHA verification.');
        setTosChallenge(null);
      } else if (isSignedIn) {
        setSuccess('Sign in successful!');
        setError('');
        setStep('auth');
      }
    } catch (err) {
      setError(err.message || 'Failed to accept Terms of Service');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Sign Up
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
            'custom:tosValidity': tosSha
          },
          validationData: { token: recaptchaToken }
        }
      });
      setStep('confirmSignUp');
      setSuccess('Sign up successful! Please enter the code sent to your email.');
      setError('');
    } catch (err) {
      setError(err.message || 'Sign up failed. Please try again.');
      setSuccess('');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Confirm Sign Up
  const handleConfirmSignUp = async (e) => {
    if (e) e.preventDefault();

    if (!confirmationCode) {
      setError('Please enter the confirmation code');
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
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Sign Out
  const handleSignOut = async () => {
    try {
      await signOut();
      setSuccess('Signed out successfully!');
      setUserSession(null);
      setFormData({ email: '', password: '', confirmPassword: '' });
      setConfirmationCode('');
      setStep('auth');
    } catch (error) {
      setError('Sign out failed: ' + error.message);
    }
  };

  // Toggle between login/signup
  const toggleAuthMode = () => {
    setIsLogin(!isLogin);
    setError('');
    setSuccess('');
    setFormData({ email: '', password: '', confirmPassword: '' });
  };

  // ToS Modal component
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
        <div className="tos-sha">Content Hash: {tosSha.substring(0, 12)}...</div>
      </div>
    </div>
  );

  // Render ToS challenge screen
  const renderTosChallenge = () => (
    <div className="auth-card">
      <div className="auth-header">
        <h2>Updated Terms of Service</h2>
        <p>Please review and accept the updated terms to continue</p>
      </div>
      
      <div className="tos-container">
        <ReactMarkdown>{tosContent}</ReactMarkdown>
      </div>

      <div className="tos-acceptance">
        <label>
          <input
            type="checkbox"
            checked={acceptedTos}
            onChange={(e) => setAcceptedTos(e.target.checked)}
          />
          I accept the Terms of Service
        </label>
        
        <button
          onClick={handleTosAccept}
          disabled={!acceptedTos || isLoading}
          className="submit-button"
        >
          {isLoading ? 'Processing...' : 'Continue'}
        </button>
      </div>
    </div>
  );

  return (
    <div className="auth-container">
      {showTosModal && <TosModal />}
      
      {step === 'tos' ? renderTosChallenge() : (
        <div className="auth-card">
          <div className="auth-header">
            <h2>
              {step === 'confirmSignUp' 
                ? 'Confirm Email' 
                : isLogin 
                  ? 'Sign In' 
                  : 'Create Account'}
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

          {step === 'confirmSignUp' ? (
            <form className="auth-form" onSubmit={handleConfirmSignUp}>
              <div className="input-group">
                <input
                  type="text"
                  placeholder="Confirmation Code"
                  value={confirmationCode}
                  onChange={(e) => setConfirmationCode(e.target.value)}
                />
              </div>
              <button type="submit" className="submit-button">
                {isLoading ? 'Verifying...' : 'Confirm'}
              </button>
            </form>
          ) : (
            <form className="auth-form" onSubmit={isLogin ? handleSignIn : handleSignUp}>
              <div className="form-fields">
                <div className="input-group">
                  <div className="input-icon">
                    <Mail />
                  </div>
                  <input
                    type="email"
                    placeholder="Email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    required
                  />
                </div>

                <div className="input-group">
                  <div className="input-icon">
                    <Lock />
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Password"
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    required
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff /> : <Eye />}
                  </button>
                </div>

                {!isLogin && (
                  <div className="input-group">
                    <div className="input-icon">
                      <Lock />
                    </div>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Confirm Password"
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      required
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
                      Terms of Service
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

              <button
                type="submit"
                className="submit-button"
                disabled={isLoading || (!isLogin && !acceptedTos)}
              >
                {isLoading ? (
                  <span>Processing...</span>
                ) : (
                  <>
                    <span>{isLogin ? 'Sign In' : 'Sign Up'}</span>
                    <ArrowRight className="button-icon" />
                  </>
                )}
              </button>
            </form>
          )}

          {step === 'auth' && isLogin && (
            <div className="forgot-password">
              <button className="text-link">
                Forgot your password?
              </button>
            </div>
          )}
        </div>
      )}
      
      {userSession && (
        <div className="sign-out-container">
          <button onClick={handleSignOut} className="text-link">
            Sign Out
          </button>
        </div>
      )}
    </div>
  );
}
