abstract class Sqrl::Identity
  @key : Key
  property check : StaticArray(UInt8, CHECK_LEN)
  property salt : StaticArray(UInt8, SALT_LEN)
  property _n : Int32
  property _r : Int32
  property _p : Int32

  abstract def recover_master_key(using password : String) : Key
end
