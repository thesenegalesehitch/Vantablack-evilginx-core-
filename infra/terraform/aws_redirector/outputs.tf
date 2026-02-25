output "public_ip" {
  value = aws_instance.redirector.public_ip
}

output "public_dns" {
  value = aws_instance.redirector.public_dns
}
