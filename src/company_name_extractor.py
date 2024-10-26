import re
import spacy

class CompanyNameExtractor:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")

    def determine_company_name(self, sender, subject, body):
        domain_pattern = re.compile(r'@([a-zA-Z0-9.-]+)')
        domain_match = domain_pattern.search(sender)
        if domain_match:
            domain = domain_match.group(1)
            company_name = domain.split('.')[0]
            return company_name

        doc = self.nlp(subject + " " + body)
        for ent in doc.ents:
            if ent.label_ == "ORG":
                return ent.text

        return 'Unknown'
