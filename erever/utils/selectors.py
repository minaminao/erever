import requests
from typing import Dict, Any, Optional

SELECTOR_LOOKUP_URL = "https://api.openchain.xyz/signature-database/v1/lookup"


def lookup_selector(selector: str, filter_results: bool = True) -> Optional[Dict[str, Any]]:
    """
    Look up a function selector in the OpenChain signature database.

    Args:
        selector: The function selector (e.g., "0x19ff1d21")
        filter_results: Whether to filter the results (default: True)

    Returns:
        Dictionary containing the API response, or None if request fails

    Example response format:
        {
            "ok": true,
            "result": {
                "event": {},
                "function": {
                    "0x19ff1d21": [
                        {
                            "name": "hello()",
                            "filtered": false
                        }
                    ]
                }
            }
        }
    """
    try:
        # Make the API request
        params = {"function": selector, "filter": str(filter_results).lower()}

        headers = {"accept": "application/json"}

        response = requests.get(SELECTOR_LOOKUP_URL, params=params, headers=headers)
        response.raise_for_status()

        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Error making request to OpenChain API: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def get_function_signatures(selector: str, filter_results: bool = True) -> list:
    """
    Get function signatures for a given selector.

    Args:
        selector: The function selector (e.g., "0x19ff1d21")
        filter_results: Whether to filter the results (default: True)

    Returns:
        List of function signature dictionaries, empty list if not found or error
    """

    # Ensure selector starts with 0x
    if not selector.startswith("0x"):
        selector = "0x" + selector

    result = lookup_selector(selector, filter_results)

    if not result or not result.get("ok"):
        return []

    function_data = result.get("result", {}).get("function", {})
    return function_data.get(selector, [])


def get_function_signature(selector: str, filter_results: bool = True) -> Optional[str]:
    signatures = get_function_signatures(selector, filter_results)
    return signatures[0]["name"] if signatures else None


def print_selector_info(selector: str, filter_results: bool = True) -> None:
    """
    Print formatted information about a selector.

    Args:
        selector: The function selector (e.g., "0x19ff1d21")
        filter_results: Whether to filter the results (default: True)
    """
    signatures = get_function_signatures(selector, filter_results)

    if not signatures:
        print(f"No signatures found for selector {selector}")
        return

    print(f"Selector {selector}:")
    for sig in signatures:
        name = sig.get("name", "Unknown")
        filtered = sig.get("filtered", False)
        status = "filtered" if filtered else "unfiltered"
        print(f"  - {name} ({status})")


# Example usage
if __name__ == "__main__":
    # Test with the example selector
    test_selector = "0x19ff1d21"
    result = lookup_selector(test_selector)

    if result:
        print("API Response:")
        print(result)
        print("\nFunction signatures:")
        print_selector_info(test_selector)
    else:
        print("Failed to get response from API")
