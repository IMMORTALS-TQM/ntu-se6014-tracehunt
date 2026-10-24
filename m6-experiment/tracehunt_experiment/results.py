"""One completeness policy shared by smoke summaries and the comparator."""

def result_complete(tool, value):
    if tool=='search_events':
        return value.get('total_relation')=='eq' and value.get('returned')==value.get('total_matches')
    if tool=='aggregate_events':
        return value.get('truncated') is False
    if tool=='run_sequence_query':
        return value.get('complete') is True
    if tool=='fetch_evidence':
        return value.get('found')==value.get('requested') and not value.get('missing_ids')
    return True
