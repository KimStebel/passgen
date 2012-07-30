package passgen

import org.apache.commons.codec.digest.DigestUtils
import java.io.BufferedReader
import java.io.FileReader
import java.io.BufferedWriter
import java.io.FileWriter

class PasswordConstraints(val maxLength:Int, val allowedCharacters:String) {
  if (allowedCharacters.toSet.size != allowedCharacters.size) {
    throw new IllegalArgumentException("duplicate chars in allowedCharactgers String")
  }
  if (maxLength > 64) {
    throw new IllegalArgumentException("not more than 64 chars supported")
  }
}

class Account(val username:String, val website:String, val constraints: PasswordConstraints) {
  private def empty(s:String) = s == null || s.trim == ""
    
  if (empty(username) || empty(website)) {
    throw new IllegalArgumentException("username and website must not be empty")
  }
   override def toString = {
     username + "\n" + 
     website + "\n" + 
     constraints.maxLength + "\n" + 
     constraints.allowedCharacters
   }
  
}

object Account {
  def fromString(s:String):Account = {
    val Array(username, website, maxLength, allowedCharacters) = s.split("\n")
    val constraints = new PasswordConstraints(maxLength.toInt, allowedCharacters)
    new Account(username, website, constraints)
  }
  def read(reader:BufferedReader):Option[Account] = try {
    val s = Stream.continually(reader.readLine()).take(4).reduce(_ + "\n" + _)
    Some(fromString(s))
  } catch {
    case _:Exception => None
  }
}

object Main {
  val atozLower = "abcdefghijklmnopqrstuvwxyz"
  val atozUpper = atozLower.toUpperCase
  val alpha = atozLower + atozUpper
  val decimal = "0123456789"
  val hex = "0123456789ABCDEF"
  val alphaNum = alpha + decimal
  val specialAscii = """^°!"§$%&/()=?`´\}][{@+*~#'-_.:,;<>|"""
  val allAscii = alphaNum + specialAscii
  val charSets = Seq(
    "1) a to z lowercase" -> atozLower,
    "2) A to Z uppercase" -> atozUpper,
    "3) 1 and 2" -> alpha,
    "4) 0 to 9" -> decimal,
    "5) 0 to F (hexadecimal)" -> hex,
    "6) 3 and 4" -> alphaNum,
    "7) 6 and special ascii characters" -> allAscii
  )
  
  def main(args:Array[String]) {
    val fileName = "accounts.txt"
    val accounts = readFile(fileName)
    println("1) calculate password of existing account")
    println("2) create new account")
    Console.readLine().toInt match {
      case 1 => {
        println("enter your master password: ")
        val masterPassword = Console.readLine()
        accounts.zipWithIndex.map{ case (account, index) => {
          println(index + ") " + account.username + "@" + account.website)
        }}
        println("choose the account: ")
        val account = accounts(Console.readLine().toInt)
        println("your password is " + password(masterPassword, account))
    
      }
      case 2 => {
        writeFile(fileName, createAccount() :: accounts) 
      }
    }
  }
  
  def createAccount():Account = {
    println("enter account name: ")
    val accountName = Console.readLine()
    println("enter website name: ")
    val website = Console.readLine()
    println("enter maximum length: ")
    val maxLength = Console.readLine().toInt
    charSets.foreach{ case (desc, set) => println(desc)}
    println("choose charset: ")
    val charSet = charSets(Console.readLine().toInt - 1)._2
    println("enter master password: ")
    val masterPassword = Console.readLine()
    val constraints = new PasswordConstraints(maxLength, charSet)
    val account = new Account(accountName, website, constraints)
    println("your password is " + password(masterPassword, account))
    account
  }
  
  def readFile(fileName:String):List[Account] = {
    val reader = new BufferedReader(new FileReader(fileName))
    val res = Stream.continually(Account.read(reader)).takeWhile(None!=).flatten.toList
    reader.close()
    res
  }
  
  def writeFile(fileName:String, accounts:List[Account]) = {
    val writer = new BufferedWriter(new FileWriter(fileName))
    accounts.foreach(account => {
      writer.write(account.toString + "\n")
    })
    writer.close()
  }
  
  def encode(hash:Array[Byte], constraints:PasswordConstraints):String = {
    val hashPart = hash.take(constraints.maxLength)
    val ac = constraints.allowedCharacters
    hashPart.map(byt => {
      constraints.allowedCharacters((byt.toInt + 128) % ac.size)
    }).foldLeft("")(_+_)
  }
  
  def password(masterPassword:String, account:Account) = {
    val hash = DigestUtils.sha512(masterPassword + account.username + account.website)
    encode(hash, account.constraints)
  }
}
