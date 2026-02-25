variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "allowed_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "domain" {
  type = string
}

variable "letsencrypt_email" {
  type = string
}

variable "wg_cidr" {
  type    = string
  default = "10.20.0.0/24"
}

variable "wg_server_address" {
  type    = string
  default = "10.20.0.1/24"
}

variable "wg_peer_address" {
  type    = string
  default = "10.20.0.2"
}

variable "wg_peer_allowed_ips" {
  type    = string
  default = "10.20.0.2/32"
}

variable "wg_peer_public_key" {
  type = string
}
