from django.contrib import admin
from ageis_app.models import *
# Register your models here.
admin.site.register([ExtendedUserModel,Clients,Testimonials,JobCategories,Country,State,district,JobType,Jobs,AppliedJobs,AboutUs,Experience,Qualification,Skills,Leads,RecentlySearchedJobs])