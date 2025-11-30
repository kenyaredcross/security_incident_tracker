import frappe
from frappe import _
from frappe.utils import strip_html

def sanitize_output(data):
    """ Remove all HTML tags from a payload"""

    if isinstance(data, dict):
        return {k : sanitize_output(v) for k, v in data.items()}


    elif isinstance(data, list):
        return [sanitize_output(i) for i in data]
    
    elif isinstance(data, str):
        return strip_html(data).strip()
    

    return data



@frappe.whitelist(allow_guest=False)
def get_security_incidents(limit=100):
    try:
        limit = int(limit)

        security_incidents = frappe.db.get_all(
            "Security Incident",
            fields=["name",
            "is_internal",
            "name_of_incident",
            "start_date",
            "end_date",            
            "incident_category",
            "act",
            "specify_incident_act",
            "severity",
            "status",
            "incident_narative",                      
            ], 
            limit = limit, 
            order_by="modified desc"        

        )

        for incident in security_incidents:
            parent = incident["name"]
            incident["location"] = frappe.db.get_all (
                "Incident Location",
                filters={"parent": parent},
                fields = ["specific_location", "county", "sub_county","remarks"]
            )

            incident["damage_report"] = frappe.db.get_all(
                "Nature of Damage", filters = {"parent": parent}, 
                fields = ["damages", "quantity", "description"]

            ) 

            incident["sitrep2"]  = frappe.db.get_all(
                "Security Incident SitRep Link",
                filters = {"parent": parent},
                fields = ["sitrep", "submitted_by","situation_trend", "date_time", "summary"],
                
            )

            incident["advisory"] = frappe.db.get_all(
                "Advisory", 
                filters = {"parent": parent},
                fields = ["issued_time", "advisory_type", "audience", "message"], 

                
            ) 

        
        # Sanitize the data to remove html tags

        sanitize_output(security_incidents)            

        return {"success": True, "data": security_incidents}


    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "API get_security_incidents")
        return {"success":False, "error": str(e)}