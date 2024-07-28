import frappe
from frappe.model.document import Document


class Character(Document):
	def get_character_name_by_id(character_id):
		"""
		Get the character name by character ID.

		:param character_id: The ID of the character.
		:return: The name of the character.
		:raises: frappe.DoesNotExistError if the character is not found.
		"""
		character_name = frappe.db.get_value("Character", character_id, "character_name")
		if not character_name:
			frappe.throw(f"No character found with ID '{character_id}'")
		return character_name

	def get_character_id_by_name(character_name):
		"""
		Get the character ID by character name.

		:param character_name: The name of the character.
		:return: The ID of the character.
		:raises: frappe.DoesNotExistError if the character is not found.
		"""
		character_id = frappe.db.get_value("Character", {"character_name": character_name}, "name")
		if not character_id:
			frappe.throw(f"No character found with name '{character_name}'")
		return character_id