# company/models.py

from django.db import models
from accounts.models import CustomUser

class CompanyType(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class Company(models.Model):
    name = models.CharField(max_length=100)
    company_type = models.ForeignKey(CompanyType, on_delete=models.CASCADE)
    ceo = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='ceo_of')
    executive_director = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='executive_director_of')
    description = models.TextField(blank=True, null=True)
    founded_date = models.DateField()

    def save(self, *args, **kwargs):
        if self.executive_director and self.executive_director.role != CustomUser.EXECUTIVE_DIRECTOR:
            raise ValueError('Assigned executive director must have the Executive Director role.')
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.name} ({self.company_type.name})'


class Department(models.Model):
    name = models.CharField(max_length=100)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='departments')
    manager = models.ForeignKey('employee.Employee', on_delete=models.SET_NULL, related_name='managed_departments', null=True, blank=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return f'{self.name} in {self.company.name}'


class DepartmentEmployee(models.Model):
    employee = models.ForeignKey('employee.Employee', on_delete=models.CASCADE, related_name='departments')
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='employees')
    date_joined = models.DateField()

    def __str__(self):
        return f'{self.employee.user.username} in {self.department.name}'
