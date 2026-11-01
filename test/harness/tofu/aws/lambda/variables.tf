variable "run_id" {
  description = "Unique identifier for this harness run; tagged onto every resource."
  type        = string
}

variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
  default     = "cloud-auth-test"
}

variable "region" {
  description = "Region the function runs in."
  type        = string
  default     = "us-east-1"
}

variable "zip_path" {
  description = "Zip containing the verifier as `bootstrap` (provided.al2023). up.sh builds it; empty is only valid for destroy."
  type        = string
  default     = ""
}
