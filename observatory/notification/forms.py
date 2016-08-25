from django import forms

class SubscribeUnsubscribeForm(forms.Form):
	email = forms.EmailField(label='Email address')
	name = forms.CharField(label='CN / DNS name')