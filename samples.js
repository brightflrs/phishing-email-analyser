/*
 * Fictional demonstration emails for the Phishing Email Analyser.
 *
 * SAFETY NOTES
 * - Every person, company and address here is invented.
 * - Domains use reserved names ending in ".example" (which never resolve to a real website),
 *   or "example.com" / "example.net" (reserved for documentation).
 * - IP addresses are from 192.0.2.0/24, a range reserved for documentation.
 * - The one shortened link is a non-working placeholder path.
 */
var SAMPLE_EMAILS = [
  {
    id: 'obvious',
    name: '1. Obvious phishing',
    summary: 'Crude threats, a raw IP address, and a direct request for a password and code.',
    text: [
      'URGENT!!! Your account will be SUSPENDED within 24 hours.',
      '',
      'Dear valued customer,',
      '',
      'We detected unusual sign-in activity on your account. To avoid permanent closure, you must act immediately.',
      '',
      'Enter your password and the verification code sent to your phone here:',
      'http://192.0.2.45/secure/login/verify',
      '',
      'Failure to respond will result in your account being closed.',
      'Do not tell anyone about this message.',
      '',
      'Account Security Team'
    ].join('\n')
  },
  {
    id: 'sophisticated',
    name: '2. Sophisticated phishing',
    summary: 'Polished, personal-sounding, with a mismatched Reply-To and failed sender checks in the headers.',
    text: [
      'From: Jordan Lee (HR Benefits) <hr-benefits@corp-portal.example>',
      'Reply-To: HR Benefits Team <benefits.helpdesk@freemail.example>',
      'Subject: Action required: updated benefits enrollment',
      'Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=corp-portal.example; dkim=none; dmarc=fail (p=reject) header.from=corp-portal.example',
      '',
      'Hi Sam,',
      '',
      'As part of the annual benefits review, HR needs you to confirm your details before the end of the day. Please open the updated enrollment form below and confirm your information:',
      '',
      'https://hr-benefits-portal.example/enrol?id=7731',
      '',
      'You will be asked to log in with your work credentials to continue.',
      '',
      'Thank you,',
      'Jordan Lee',
      'HR Benefits'
    ].join('\n')
  },
  {
    id: 'microsoft365',
    name: '3. Fake Microsoft 365 warning',
    summary: 'Impersonates Microsoft with a lookalike domain that only starts with a Microsoft address.',
    text: [
      'From: Microsoft 365 Message Center <no-reply@m365-account-verify.example>',
      'Subject: Action required: your mailbox will be deactivated',
      '',
      'Microsoft 365 Security Team',
      '',
      'We were unable to verify your mailbox settings. Your Microsoft 365 account will be deactivated in 2 hours unless you validate your account now.',
      '',
      'To keep your mailbox active, verify your account here:',
      'https://account.microsoft.com.reset-verify.example/signin?session=88213',
      '',
      'If you do not respond, your access to Outlook and OneDrive will be restricted.',
      '',
      'Microsoft 365 Support'
    ].join('\n')
  },
  {
    id: 'parcel',
    name: '4. Fake parcel delivery',
    summary: 'A small "redelivery fee" and a shortened link that hides its destination.',
    text: [
      'Dear customer,',
      '',
      'We attempted to deliver your parcel (tracking ref PH-7731-45) but the delivery address is incomplete. Your parcel is now on hold.',
      '',
      'A redelivery fee of PHP 49.00 is required. Please pay within 24 hours to avoid return to sender:',
      'http://bit.ly/example-parcel-fee',
      '',
      'Act now to keep your delivery.',
      '',
      'Parcel Services'
    ].join('\n')
  },
  {
    id: 'bec-invoice',
    name: '5. Fake invoice (business email compromise)',
    summary: 'Pretends to be a supplier, asks to change bank details, urges secrecy, and includes a macro-enabled file.',
    text: [
      'Hi Ramon,',
      '',
      'Please note that our bank details have changed effective immediately. Kindly update your records and send all payments for invoice INV-20417 to the new account below.',
      '',
      'The invoice is now overdue and payment of PHP 486,500.00 is due today. The attached statement (Invoice_20417.xlsm) shows the details. Enable editing and content to view the full statement.',
      '',
      'Please keep this confidential while we finalise the audit.',
      '',
      'Thanks,',
      'Maria',
      'Finance'
    ].join('\n')
  },
  {
    id: 'legitimate',
    name: '6. Legitimate email',
    summary: 'A routine bill notice with no pressure, passes all sender checks, and sends you to a normal address.',
    text: [
      'From: Meridian Utilities <billing@example.com>',
      'Subject: Your September electricity bill is ready',
      'Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com',
      '',
      'Hello Ana,',
      '',
      'Your September electricity bill is now available. You can view it by signing in to your account on our official app, or by visiting www.example.com/billing.',
      '',
      'No action is needed if you have already set up automatic payment. If you have questions about your bill, please call the number printed on your statement.',
      '',
      'Kind regards,',
      'Meridian Utilities Customer Care'
    ].join('\n')
  }
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SAMPLE_EMAILS;
}
