from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm

from apps.accounts.models import User


class SignUpForm(UserCreationForm):
    """회원가입 폼 - 이메일 기반 로그인"""

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
        fields = ("email", "nickname", "password1", "password2")

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

    def save(self, commit=True):
        """UserManager.create_user 사용하여 저장"""
        user = User.objects.create_user(
            email=self.cleaned_data["email"],
            nickname=self.cleaned_data["nickname"],
            password=self.cleaned_data["password1"],
        )
        return user


class LoginForm(forms.Form):
    """로그인 폼 - 이메일 기반 로그인"""

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "이메일"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "비밀번호"})
    )

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email and password:
            self.user_cache = authenticate(self.request, username=email, password=password)
            if self.user_cache is None:
                raise forms.ValidationError("이메일 또는 비밀번호가 올바르지 않습니다.")
            if not self.user_cache.is_active:
                raise forms.ValidationError("비활성화된 계정입니다.")
        return self.cleaned_data

    def get_user(self):
        return self.user_cache
