import django_filters
from .models import Certificate
 
class CertFilter(django_filters.FilterSet):
    class Meta:
        model = Certificate
        fields = {
            'not_before' :  ['lt',  'gt'], 
            'not_after':  ['lt',  'gt']
            }

