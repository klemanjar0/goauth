package email

import (
	"bytes"
	"fmt"
	"goauth/internal/constants"
	"html/template"
	"net/smtp"
	"os"
)

type Config struct {
	SMTPHost string
	SMTPPort string
	SMTPUser string
	From     string
	Password string
}

var config Config

func Init(cfg Config) {
	config = cfg
}

func SendVerificationEmail(to, token string) error {
	subject := "Confirm your email"
	confirmLink := fmt.Sprintf("%s/verify-email?token=%s", os.Getenv(constants.APP_URL), token)

	htmlBody := renderVerificationTemplate(confirmLink)

	return sendEmail(to, subject, htmlBody)
}

func SendPasswordResetEmail(to, token string) error {
	subject := "Reset your password"
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", os.Getenv(constants.APP_URL), token)

	htmlBody := renderPasswordResetTemplate(resetLink)

	return sendEmail(to, subject, htmlBody)
}

func sendEmail(to, subject, htmlBody string) error {
	auth := smtp.PlainAuth("", config.SMTPUser, config.Password, config.SMTPHost)

	headers := make(map[string]string)
	headers["From"] = config.From
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + htmlBody

	addr := fmt.Sprintf("%s:%s", config.SMTPHost, config.SMTPPort)
	return smtp.SendMail(addr, auth, config.From, []string{to}, []byte(message))
}

func renderVerificationTemplate(confirmLink string) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h1 style="color: #333333; margin: 0 0 20px 0; font-size: 24px;">Confirm your email</h1>
                            <p style="color: #666666; line-height: 1.6; margin: 0 0 30px 0; font-size: 16px;">
                                Thanks for signing up! Please click the button below to verify your email address.
                            </p>
                            <table cellpadding="0" cellspacing="0" style="margin: 0 0 30px 0;">
                                <tr>
                                    <td align="center" style="background-color: #007bff; border-radius: 4px;">
                                        <a href="{{.ConfirmLink}}" style="display: inline-block; padding: 14px 40px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: bold;">
                                            Verify email
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            <p style="color: #999999; line-height: 1.6; margin: 0; font-size: 14px;">
                                If the button doesn't work, copy and paste this link into your browser:
                            </p>
                            <p style="color: #007bff; word-break: break-all; margin: 10px 0 0 0; font-size: 14px;">
                                {{.ConfirmLink}}
                            </p>
                            <hr style="border: none; border-top: 1px solid #eeeeee; margin: 30px 0;">
                            <p style="color: #999999; margin: 0; font-size: 12px;">
                                This link will expire in 24 hours. If you didn't create an account, you can ignore this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`

	var buf bytes.Buffer
	t := template.Must(template.New("email").Parse(tmpl))
	t.Execute(&buf, map[string]string{"ConfirmLink": confirmLink})
	return buf.String()
}

func renderPasswordResetTemplate(resetLink string) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h1 style="color: #333333; margin: 0 0 20px 0; font-size: 24px;">reset your password</h1>
                            <p style="color: #666666; line-height: 1.6; margin: 0 0 30px 0; font-size: 16px;">
                                we received a request to reset your password. click the button below to create a new password.
                            </p>
                            <table cellpadding="0" cellspacing="0" style="margin: 0 0 30px 0;">
                                <tr>
                                    <td align="center" style="background-color: #dc3545; border-radius: 4px;">
                                        <a href="{{.ResetLink}}" style="display: inline-block; padding: 14px 40px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: bold;">
                                            reset password
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            <p style="color: #999999; line-height: 1.6; margin: 0; font-size: 14px;">
                                or copy and paste this link:
                            </p>
                            <p style="color: #dc3545; word-break: break-all; margin: 10px 0 0 0; font-size: 14px;">
                                {{.ResetLink}}
                            </p>
                            <hr style="border: none; border-top: 1px solid #eeeeee; margin: 30px 0;">
                            <p style="color: #999999; margin: 0; font-size: 12px;">
                                this link will expire in 1 hour. if you didn't request a password reset, you can safely ignore this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`

	var buf bytes.Buffer
	t := template.Must(template.New("email").Parse(tmpl))
	t.Execute(&buf, map[string]string{"ResetLink": resetLink})
	return buf.String()
}
