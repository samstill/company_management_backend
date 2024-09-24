from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CompanyViewSet, DepartmentViewSet, DepartmentEmployeeViewSet

router = DefaultRouter()
router.register(r'companies', CompanyViewSet, basename='company')
router.register(r'companies/(?P<company_id>\d+)/departments', DepartmentViewSet, basename='department')
router.register(r'departments/(?P<department_id>\d+)/employees', DepartmentEmployeeViewSet, basename='department-employee')

urlpatterns = [
    path('', include(router.urls)),
]
