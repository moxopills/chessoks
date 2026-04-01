from django.db import models


class SignupEmailToken(models.Model):
    """회원가입 전 이메일 인증을 위한 토큰"""

    email = models.EmailField(help_text="인증 대상 이메일")
    token = models.CharField(max_length=64, unique=True, db_index=True, help_text="내부 토큰")
    code_hash = models.CharField(max_length=64, help_text="인증 코드 해시")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="토큰 만료 시간")
    is_used = models.BooleanField(default=False, help_text="사용 여부")
    used_at = models.DateTimeField(null=True, blank=True, help_text="사용 시간")
    attempts = models.PositiveSmallIntegerField(default=0, help_text="인증 시도 횟수")

    class Meta:
        db_table = "signup_email_tokens"
        ordering = ["-created_at"]
        verbose_name = "회원가입 이메일 토큰"
        verbose_name_plural = "회원가입 이메일 토큰"
        indexes = [
            models.Index(fields=["email", "is_used"], name="idx_signup_email_used"),
            models.Index(fields=["expires_at"], name="idx_signup_email_expires"),
        ]

    def __str__(self):
        return f"[회원가입 이메일] {self.email} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
