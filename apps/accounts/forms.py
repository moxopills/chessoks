from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from apps.accounts.models import User


class SignUpForm(UserCreationForm):
    """회원가입 폼"""

    email = forms.EmailField(
        max_length=100,
        required=True,
        help_text="이메일 주소를 입력하세요",
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "이메일"}),
    )

    nickname = forms.CharField(
        max_length=50,
        required=True,
        help_text="게임에서 사용할 닉네임",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "닉네임"}),
    )

    class Meta:
        model = User
        fields = ("username", "email", "nickname", "password1", "password2")
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control", "placeholder": "사용자명"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["password1"].widget = forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "비밀번호"}
        )
        self.fields["password2"].widget = forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "비밀번호 확인"}
        )

    def clean_email(self):
        """이메일 중복 체크"""
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("이미 사용 중인 이메일입니다.")
        return email

    def clean_nickname(self):
        """닉네임 중복 체크"""
        nickname = self.cleaned_data.get("nickname")
        if User.objects.filter(nickname=nickname).exists():
            raise forms.ValidationError("이미 사용 중인 닉네임입니다.")
        return nickname


class LoginForm(AuthenticationForm):
    """로그인 폼"""

    username = forms.CharField(
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "사용자명 또는 이메일"}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "비밀번호"})
    )
